package version

import (
	"runtime/debug"
	"testing"
)

func TestEffectiveVersionPrefersExplicitVersion(t *testing.T) {
	got := Resolve("v1.2.3", &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}}, true)
	if got != "v1.2.3" {
		t.Fatalf("Resolve() = %q, want %q", got, "v1.2.3")
	}
}

func TestEffectiveVersionFallsBackToBuildInfoWhenExplicitIsDev(t *testing.T) {
	got := Resolve("dev", &debug.BuildInfo{Main: debug.Module{Version: "v1.4.0"}}, true)
	if got != "v1.4.0" {
		t.Fatalf("Resolve() = %q, want %q", got, "v1.4.0")
	}
}

func TestEffectiveVersionFallsBackToBuildInfoWhenExplicitIsBlank(t *testing.T) {
	got := Resolve("", &debug.BuildInfo{Main: debug.Module{Version: "v1.4.0"}}, true)
	if got != "v1.4.0" {
		t.Fatalf("Resolve() = %q, want %q", got, "v1.4.0")
	}
}

func TestEffectiveVersionFallsBackToDevWhenBuildInfoIsDevel(t *testing.T) {
	got := Resolve("dev", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true)
	if got != "dev" {
		t.Fatalf("Resolve() = %q, want %q", got, "dev")
	}
}

func TestEffectiveVersionFallsBackToDevWhenBuildInfoIsEmpty(t *testing.T) {
	got := Resolve("dev", &debug.BuildInfo{}, true)
	if got != "dev" {
		t.Fatalf("Resolve() = %q, want %q", got, "dev")
	}
}

func TestEffectiveVersionFallsBackToDevWhenBuildInfoUnavailable(t *testing.T) {
	got := Resolve("dev", nil, false)
	if got != "dev" {
		t.Fatalf("Resolve() = %q, want %q", got, "dev")
	}
}

func TestDescribeFromReadsVCSSettings(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v3.0.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
			{Key: "vcs.time", Value: "2026-09-30T12:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
			{Key: "-buildmode", Value: "exe"},
		},
	}
	got := DescribeFrom("dev", info, true, "go1.27.1", "linux", "arm64")
	want := Info{
		Version:   "v3.0.0",
		Commit:    "0123456789abcdef0123456789abcdef01234567",
		Modified:  true,
		BuildTime: "2026-09-30T12:00:00Z",
		GoVersion: "go1.27.1",
		OS:        "linux",
		Arch:      "arm64",
	}
	if got != want {
		t.Fatalf("DescribeFrom() = %+v, want %+v", got, want)
	}
}

func TestDescribeFromReportsUnknownWithoutBuildInfo(t *testing.T) {
	got := DescribeFrom("v3.0.0-rc.1", nil, false, "", "windows", "amd64")
	want := Info{Version: "v3.0.0-rc.1", Commit: Unknown, BuildTime: Unknown, GoVersion: Unknown, OS: "windows", Arch: "amd64"}
	if got != want {
		t.Fatalf("DescribeFrom() = %+v, want %+v", got, want)
	}
}

func TestDescribeFromIgnoresBlankVCSValues(t *testing.T) {
	info := &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "  "}, {Key: "vcs.modified", Value: "false"}}}
	got := DescribeFrom("", info, true, "go1.27.1", "darwin", "arm64")
	if got.Commit != Unknown || got.BuildTime != Unknown || got.Modified || got.Version != "dev" {
		t.Fatalf("DescribeFrom() = %+v", got)
	}
}

func TestDescribeUsesRuntimeDetails(t *testing.T) {
	got := Describe()
	if got.Version == "" || got.GoVersion == "" || got.OS == "" || got.Arch == "" {
		t.Fatalf("Describe() returned blank fields: %+v", got)
	}
}
