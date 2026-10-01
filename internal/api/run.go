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
	"github.com/brumbelow/layerleak/v3/internal/scanservice"
	"github.com/brumbelow/layerleak/v3/internal/storage"
)

const defaultShutdownTimeout = 30 * time.Second

// ServerOptions configures the HTTP listener and the drain sequence that runs
// when the serve context is cancelled.
type ServerOptions struct {
	// Addr is the host:port ListenAndServe binds.
	Addr              string
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
	handler    *Handler
	httpServer *http.Server
	options    ServerOptions
	logger     *slog.Logger
	cancelBase context.CancelFunc
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
	return &Server{
		handler:    handler,
		httpServer: httpServer,
		options:    options,
		logger:     options.Logger,
		cancelBase: cancelBase,
	}
}

// ListenAndServe binds Addr and serves until ctx is cancelled, then drains.
func (s *Server) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.options.Addr)
	if err != nil {
		return fmt.Errorf("listen on api address: %w", err)
	}
	return s.Serve(ctx, listener)
}

// Serve accepts connections on listener until ctx is cancelled and then runs
// the drain sequence. It returns nil after a clean shutdown and the serve or
// shutdown error otherwise. Shutdown closes the listener.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	served := make(chan error, 1)
	go func() {
		err := s.httpServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		served <- err
	}()

	select {
	case err := <-served:
		s.cancelBase()
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
			return serveError(err)
		}
	}

	s.cancelBase()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.options.ShutdownTimeout)
	defer cancel()
	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown api server: %w", err)
	}
	if err := serveError(<-served); err != nil {
		return err
	}
	s.logger.Info("api stopped")
	return nil
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
	logger, err := newDefaultLogger(cfg.LogLevel)
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

	server := NewServer(scanservice.New(cfg, store), store, ServerOptions{
		Addr:              cfg.APIAddr,
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
			ResponseTimeout:    cfg.APIResponseWriteTimeout,
			Logger:             logger,
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

func newDefaultLogger(levelName string) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.TrimSpace(levelName))); err != nil {
		return nil, fmt.Errorf("parse log level: %w", err)
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})), nil
}
