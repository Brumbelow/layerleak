package main

type exitError struct {
	code int
}

func (e exitError) Error() string {
	return ""
}

func (e exitError) ExitCode() int {
	return e.code
}
