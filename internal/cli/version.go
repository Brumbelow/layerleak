package cli

import "github.com/brumbelow/layerleak/v3/internal/version"

func effectiveVersion() string {
	return version.Effective()
}
