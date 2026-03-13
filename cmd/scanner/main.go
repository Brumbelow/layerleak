package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	os.Exit(run())
}

func run() int {
	if err := newRootCmd().Execute(); err != nil {
		var coded interface {
			ExitCode() int
		}
		if errors.As(err, &coded) {
			if err.Error() != "" {
				fmt.Fprintln(os.Stderr, err)
			}
			return coded.ExitCode()
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	return 0
}
