package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
)

// signalCancellation is the context cause recorded when SIGINT or SIGTERM
// interrupted the run, so the scan command can name the signal.
type signalCancellation struct {
	signal os.Signal
}

func (e *signalCancellation) Error() string {
	return fmt.Sprintf("scan canceled by %s signal", e.signal)
}

func Run() int {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	stop := watchSignals(cancel, os.Stderr, func(ch chan<- os.Signal) {
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	}, func(ch chan<- os.Signal) {
		signal.Stop(ch)
		// With no handler left, the next SIGINT or SIGTERM terminates the
		// process immediately (the default disposition), so a scan stuck in
		// a non-cancellable section can still be force-quit.
		signal.Reset(os.Interrupt, syscall.SIGTERM)
	})
	defer stop()

	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		var coded interface {
			ExitCode() int
		}
		if errors.As(err, &coded) {
			if err.Error() != "" {
				fmt.Fprintln(os.Stderr, sanitizeProgressValue(err.Error()))
			}
			return coded.ExitCode()
		}
		fmt.Fprintln(os.Stderr, sanitizeProgressValue(err.Error()))
		return exitCodeFailure
	}

	return 0
}

// watchSignals cancels the run on the first signal, prints a note and then
// stops listening so a second signal gets the default handling (termination).
// The returned function ends the watch; it is safe to call more than once.
func watchSignals(cancel context.CancelCauseFunc, stderr io.Writer, notify, stopNotify func(chan<- os.Signal)) func() {
	signals := make(chan os.Signal, 1)
	notify(signals)
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case sig := <-signals:
			stopNotify(signals)
			_, _ = fmt.Fprintf(stderr, "interrupt received (%s), finishing... press again to force exit\n", sig)
			cancel(&signalCancellation{signal: sig})
		case <-done:
			stopNotify(signals)
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "layerleak",
		Short:         "Scan OCI images for likely secrets",
		Long:          rootLongHelp,
		Version:       effectiveVersion(),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	// Subcommands inherit the hint: usage is silenced on errors, so a bad
	// flag points at --help instead.
	cmd.SetFlagErrorFunc(usageHintFlagError)

	cmd.AddCommand(newScanCmd())
	cmd.AddCommand(newBaselineCmd())
	cmd.AddCommand(newDetectorsCmd())
	cmd.AddCommand(newVersionCmd())

	return cmd
}
