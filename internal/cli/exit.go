package cli

type exitError struct {
	code    int
	message string
}

func (e exitError) Error() string {
	return e.message
}

func (e exitError) ExitCode() int {
	return e.code
}
