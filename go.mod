module github.com/brumbelow/layerleak/v3

go 1.27.1

// npm packages installed for the browser tests can ship Go sources without a
// go.mod; keep them out of ./... so vet, lint, tests and govulncheck cover
// only layerleak's own code.
ignore ./scripts/tests/node_modules

require (
	github.com/distribution/reference v0.6.0
	github.com/klauspost/compress v1.20.1
	github.com/lib/pq v1.12.3
	github.com/opencontainers/go-digest v1.0.0
	github.com/spf13/cobra v1.10.2
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
)
