package cli

import (
	"runtime/debug"
	"strings"
)

func effectiveVersion() string {
	info, ok := debug.ReadBuildInfo()
	return resolveVersion(Version, info, ok)
}

func resolveVersion(explicit string, info *debug.BuildInfo, infoOK bool) string {
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
