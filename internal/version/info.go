package version

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Info describes the running binary. Fields that cannot be determined are
// "unknown" so output stays stable for scripts.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Modified  bool   `json:"modified"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Unknown is reported for build details the toolchain did not record.
const Unknown = "unknown"

// Describe returns the version, VCS and toolchain details of this binary.
func Describe() Info {
	info, ok := debug.ReadBuildInfo()
	return DescribeFrom(Version, info, ok, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// DescribeFrom builds an Info from explicit inputs so the precedence rules can
// be tested without a real build.
func DescribeFrom(explicit string, info *debug.BuildInfo, infoOK bool, goVersion, goos, goarch string) Info {
	result := Info{
		Version:   Resolve(explicit, info, infoOK),
		Commit:    Unknown,
		BuildTime: Unknown,
		GoVersion: strings.TrimSpace(goVersion),
		OS:        goos,
		Arch:      goarch,
	}
	if result.GoVersion == "" {
		result.GoVersion = Unknown
	}
	if !infoOK || info == nil {
		return result
	}
	for _, setting := range info.Settings {
		value := strings.TrimSpace(setting.Value)
		switch setting.Key {
		case "vcs.revision":
			if value != "" {
				result.Commit = value
			}
		case "vcs.time":
			if value != "" {
				result.BuildTime = value
			}
		case "vcs.modified":
			result.Modified = value == "true"
		}
	}
	return result
}
