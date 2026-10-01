package main

import (
	"os"

	"github.com/brumbelow/layerleak/v3/internal/cli"
)

func main() {
	os.Exit(cli.Run())
}
