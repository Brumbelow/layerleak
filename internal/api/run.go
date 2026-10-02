package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/brumbelow/layerleak/v3/internal/config"
	"github.com/brumbelow/layerleak/v3/internal/logging"
	"github.com/brumbelow/layerleak/v3/internal/scanservice"
	"github.com/brumbelow/layerleak/v3/internal/storage"
)

const defaultShutdownTimeout = 30 * time.Second

// ServerOptions configures the HTTP listener and the drain sequence that runs
// when the serve context is cancelled.
type ServerOptions struct {
	// Addr is the host:port ListenAndServe binds.
	Addr string
	// MetricsAddr, when set, is a second host:port on which ListenAndServe
	// serves GET /metrics (Prometheus text format) with the same timeouts
	// (including Handler.ResponseTimeout as the write deadline) and drain.
	// Empty disables the metrics listener. It is never the API
	// address: metrics are not exposed on the API port.
	MetricsAddr       string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	IdleTimeout       time.Duration
	// ShutdownTimeout bounds how long Shutdown waits for in-flight handlers
	// after their contexts were cancelled. Zero uses 30 s.
	ShutdownTimeout time.Duration
	// PreStopDelay is the drain window: /readyz reports 503 not_ready and new
	// scans are refused while in-flight requests keep running, so load
	// balancers can deregister the instance before anything is cancelled.
	PreStopDelay time.Duration
	Handler      HandlerOptions
	// Logger receives lifecycle events and net/http's internal errors. Nil
	// uses slog.Default().
	Logger *slog.Logger
}

func (options ServerOptions) withDefaults() ServerOptions {
	if options.ShutdownTimeout <= 0 {
		options.ShutdownTimeout = defaultShutdownTimeout
	}
	if options.PreStopDelay < 0 {
		options.PreStopDelay = 0
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.Handler.Logger == nil {
		options.Handler.Logger = options.Logger
	}
	return options
}

// Server runs the JSON API with a graceful drain: readiness flips first, the
// pre-stop delay elapses, in-flight request contexts are cancelled so scans
// abort with 503 server_shutting_down, and http.Server.Shutdown waits for
// handlers to finish.
type Server struct {
	handler       *Handler
	httpServer    *http.Server
	metricsServer *http.Server
	options       ServerOptions
	logger        *slog.Logger
	cancelBase    context.CancelFunc
}

// NewServer builds the API server from its dependencies. The scanner serves
// POST /api/v1/scans and the store backs the read endpoints and readiness.
func NewServer(scanner scanExecutor, store storage.ReadStore, options ServerOptions) *Server {
	options = options.withDefaults()
	handler := newHandler(scanner, store, options.Handler)
	baseCtx, cancelBase := context.WithCancel(context.Background())
	httpServer := &http.Server{
		Addr:              options.Addr,
		Handler:           handler,
		ReadHeaderTimeout: options.ReadHeaderTimeout,
		ReadTimeout:       options.ReadTimeout,
		IdleTimeout:       options.IdleTimeout,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
		// net/http's own messages (accept errors, TLS handshakes, panics
		// outside the middleware) join the JSON log stream.
		ErrorLog: slog.NewLogLogger(options.Logger.Handler(), slog.LevelError),
	}
	metricsServer := &http.Server{
		Addr:              options.MetricsAddr,
		Handler:           handler.MetricsHandler(),
		ReadHeaderTimeout: options.ReadHeaderTimeout,
		ReadTimeout:       options.ReadTimeout,
		// The API handlers set their own per-response deadline; the metrics
		// handler does too, and the server-wide timeout backs it so a scraper
		// that stops reading can never pin a connection for good.
		WriteTimeout: handler.options.ResponseTimeout,
		IdleTimeout:  options.IdleTimeout,
		ErrorLog:     slog.NewLogLogger(options.Logger.Handler(), slog.LevelError),
	}
	return &Server{
		handler:       handler,
		httpServer:    httpServer,
		metricsServer: metricsServer,
		options:       options,
		logger:        options.Logger,
		cancelBase:    cancelBase,
	}
}

// ListenAndServe binds Addr (and MetricsAddr when configured) and serves
// until ctx is cancelled, then drains.
func (s *Server) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.options.Addr)
	if err != nil {
		return fmt.Errorf("listen on api address: %w", err)
	}
	var metricsListener net.Listener
	if strings.TrimSpace(s.options.MetricsAddr) != "" {
		metricsListener, err = net.Listen("tcp", s.options.MetricsAddr)
		if err != nil {
			_ = listener.Close()
			return fmt.Errorf("listen on metrics address: %w", err)
		}
	}
	return s.ServeListeners(ctx, listener, metricsListener)
}

// Serve accepts API connections on listener until ctx is cancelled and then
// runs the drain sequence, without a metrics listener.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	return s.ServeListeners(ctx, listener, nil)
}

// ServeListeners serves the API on listener and, when metricsListener is not
// nil, GET /metrics on it, until ctx is cancelled. It then drains: readiness
// flips, the pre-stop delay elapses, in-flight contexts are cancelled and both
// servers shut down within ShutdownTimeout. Metrics stay scrapeable through
// the drain. It returns nil after a clean shutdown and the API serve or
// shutdown error otherwise; a metrics listener that stops early is logged and
// the API keeps serving. Shutdown closes both listeners.
func (s *Server) ServeListeners(ctx context.Context, listener, metricsListener net.Listener) error {
	served := make(chan error, 1)
	go func() {
		err := s.httpServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		served <- err
	}()
	metricsDone := make(chan struct{})
	if metricsListener != nil {
		go func() {
			defer close(metricsDone)
			if err := s.metricsServer.Serve(metricsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Error("metrics listener stopped", "error_type", fmt.Sprintf("%T", err))
			}
		}()
	} else {
		close(metricsDone)
	}

	select {
	case err := <-served:
		s.cancelBase()
		s.shutdownMetrics(metricsDone)
		return serveError(err)
	case <-ctx.Done():
	}

	s.handler.startDraining()
	s.logger.Info("api draining",
		"prestop_delay", s.options.PreStopDelay.String(),
		"shutdown_timeout", s.options.ShutdownTimeout.String(),
	)
	if s.options.PreStopDelay > 0 {
		timer := time.NewTimer(s.options.PreStopDelay)
		select {
		case <-timer.C:
		case err := <-served:
			timer.Stop()
			s.cancelBase()
			s.shutdownMetrics(metricsDone)
			return serveError(err)
		}
	}

	s.cancelBase()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.options.ShutdownTimeout)
	defer cancel()
	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		s.shutdownMetrics(metricsDone)
		return fmt.Errorf("shutdown api server: %w", err)
	}
	if err := serveError(<-served); err != nil {
		s.shutdownMetrics(metricsDone)
		return err
	}
	s.shutdownMetrics(metricsDone)
	s.logger.Info("api stopped")
	return nil
}

// shutdownMetrics stops the metrics listener (a scrape is a single quick
// response, so a short bound suffices) and waits for its serve loop to end.
func (s *Server) shutdownMetrics(done <-chan struct{}) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.metricsServer.Shutdown(shutdownCtx); err != nil {
		_ = s.metricsServer.Close()
	}
	<-done
}

func serveError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("serve api: %w", err)
}

// Run loads configuration, connects to PostgreSQL and serves the API until
// SIGINT or SIGTERM, then drains and returns. main wraps it.
func Run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger, err := newDefaultLogger(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		return fmt.Errorf("LAYERLEAK_DATABASE_URL is required for the API")
	}

	store, err := storage.NewPostgresStore(storage.PostgresConfig{
		DatabaseURL:       cfg.DatabaseURL,
		PersistRawSecrets: cfg.PersistRawSecrets,
		MaxOpenConns:      cfg.DatabaseMaxOpenConns,
		MaxIdleConns:      cfg.DatabaseMaxIdleConns,
		ConnMaxLifetime:   cfg.DatabaseConnMaxLifetime,
		ConnMaxIdleTime:   cfg.DatabaseConnMaxIdleTime,
		QueryTimeout:      cfg.DatabaseQueryTimeout,
		WriteTimeout:      cfg.DatabaseWriteTimeout,
		RequireSchema:     true,
	})
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	if !cfg.PersistRawSecrets {
		warnAboutRawSecrets(store, cfg.DatabaseQueryTimeout, logger)
	}
	warnAboutOpenListener(cfg.APIAddr, len(cfg.APIBearerTokenDigests) > 0, logger)

	server := NewServer(scanservice.New(cfg, store), store, ServerOptions{
		Addr:              cfg.APIAddr,
		MetricsAddr:       cfg.APIMetricsAddr,
		ReadHeaderTimeout: cfg.APIReadHeaderTimeout,
		ReadTimeout:       cfg.APIReadTimeout,
		IdleTimeout:       cfg.APIIdleTimeout,
		ShutdownTimeout:   cfg.APIShutdownTimeout,
		PreStopDelay:      cfg.APIPreStopDelay,
		Logger:            logger,
		Handler: HandlerOptions{
			MaxRequestBytes:    cfg.APIMaxRequestBytes,
			ScanTimeout:        cfg.APIScanTimeout,
			MaxConcurrentScans: cfg.APIMaxConcurrentScans,
			QueryTimeout:       cfg.DatabaseQueryTimeout,
			ReadinessTimeout:   cfg.APIReadinessTimeout,
			ReadinessCacheTTL:  cfg.APIReadinessCacheTTL,
			ResponseTimeout:    cfg.APIResponseWriteTimeout,
			Logger:             logger,
			BearerTokenDigests: cfg.APIBearerTokenDigests,
		},
	})

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.ListenAndServe(signalCtx)
}

type rawSecretCounter interface {
	CountRawSecrets(ctx context.Context) (storage.RawSecretCounts, error)
}

// warnAboutRawSecrets logs when the database still holds raw secret material
// from an earlier opt-in. It is a startup inventory over the findings tables,
// so it runs under the database query timeout rather than the readiness
// probe budget; the probe budget is sized for a ping and a ledger lookup.
func warnAboutRawSecrets(store rawSecretCounter, timeout time.Duration, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	counts, err := store.CountRawSecrets(ctx)
	if err != nil {
		logger.Warn("could not inspect historical raw secret storage", "error_type", fmt.Sprintf("%T", err))
		return
	}
	if counts.Total() > 0 {
		logger.Warn(
			"database still contains raw secret material from an earlier opt-in; run layerleak-purge-raw-secrets --confirm to remove it",
			"finding_values", counts.FindingValues,
			"occurrence_snippets", counts.OccurrenceSnippets,
		)
	}
}

// warnAboutOpenListener logs once at startup when the API accepts
// unauthenticated requests on an address other than loopback, the deployment
// mistake the opt-in bearer tokens exist to catch. The container image binds
// 0.0.0.0 by design, so this is a warning, not an error.
func warnAboutOpenListener(addr string, authenticated bool, logger *slog.Logger) {
	if authenticated {
		return
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "localhost" {
		return
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return
	}
	logger.Warn("api authentication is disabled on a non-loopback address; set LAYERLEAK_API_BEARER_TOKENS or place the API behind an authenticated gateway", "api_addr", addr)
}

// newDefaultLogger builds the process logger on stderr from
// LAYERLEAK_LOG_LEVEL and LAYERLEAK_LOG_FORMAT through the handler
// constructor the CLI shares (internal/logging).
func newDefaultLogger(levelName, formatName string) (*slog.Logger, error) {
	return logging.NewLogger(os.Stderr, levelName, formatName)
}
