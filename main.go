package main

import (
	"os"

	"github.com/brumbelow/layerleak/internal/cli"
)

func main() {
	os.Exit(cli.Run())
}
