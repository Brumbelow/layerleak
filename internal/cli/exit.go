package cli

// Exit codes are a stable contract for automation (README "Scan images").
const (
	// exitCodeFailure: invalid input, operational failure, persistence failure
	// or cancellation.
	exitCodeFailure = 1
	// exitCodeFindings: one or more actionable findings at or above --fail-on.
	exitCodeFindings = 2
	// exitCodeIncomplete: the scan finished with usable but incomplete
	// coverage and --allow-partial was not given.
	exitCodeIncomplete = 3
)

type exitError struct {
	code    int
	message string
	// cause keeps errors.Is/errors.As working for callers and tests (for
	// example context.DeadlineExceeded behind a friendly timeout message).
	cause error
}

func (e exitError) Error() string {
	return e.message
}

func (e exitError) ExitCode() int {
	return e.code
}

func (e exitError) Unwrap() error {
	return e.cause
}
