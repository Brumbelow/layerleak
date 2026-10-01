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
