// Package version reports the build version of layerleak binaries.
package version

import (
	"runtime/debug"
	"strings"
)

// Version is the build-time version string. Container builds set it with
// -ldflags "-X github.com/brumbelow/layerleak/v3/internal/version.Version=v3.0.0";
// module installs leave it at "dev" and resolve the version from build info.
var Version = "dev"

// Effective returns the version to report: the explicit build-time value,
// otherwise the module version recorded by the Go toolchain, otherwise "dev".
func Effective() string {
	info, ok := debug.ReadBuildInfo()
	return Resolve(Version, info, ok)
}

// Resolve applies the version precedence to explicit inputs.
func Resolve(explicit string, info *debug.BuildInfo, infoOK bool) string {
	trimmed := strings.TrimSpace(explicit)
	if trimmed != "" && trimmed != "dev" {
		return trimmed
	}
	if infoOK && info != nil {
		mainVersion := strings.TrimSpace(info.Main.Version)
		if mainVersion != "" && mainVersion != "(devel)" {
			return mainVersion
		}
	}
	return "dev"
}
