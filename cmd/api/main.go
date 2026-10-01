package main

import (
	"fmt"
	"os"

	"github.com/brumbelow/layerleak/v3/internal/api"
)

func main() {
	if err := api.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
