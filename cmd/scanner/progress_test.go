package main

import (
	"bytes"
	"strings"
	"testing"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/scanner"
)

func TestProgressRendererRendersLogoAndStatusBlock(t *testing.T) {
	var buffer bytes.Buffer
	renderer := newProgressRenderer(&buffer)

	if err := renderer.Start(progressSnapshot{
		repository:        "library/app",
		repositoriesTotal: 1,
		phase:             "Starting",
		message:           "Preparing scan",
	}); err != nil {
		t.Fatalf("renderer.Start() error = %v", err)
	}
	if err := renderer.UpdateFromScan(scanner.ProgressUpdate{
		Phase:                 scanner.ProgressPhaseManifestCompleted,
		Repository:            "library/app",
		RepositoriesCompleted: 1,
		RepositoriesTotal:     1,
		ManifestCompleted:     1,
		ManifestTotal:         2,
		FindingsFound:         7,
		CurrentPlatform:       manifest.Platform{OS: "linux", Architecture: "amd64"},
		CurrentManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Message:               "Completed linux/amd64",
	}); err != nil {
		t.Fatalf("renderer.UpdateFromScan() error = %v", err)
	}
	if err := renderer.Finish(); err != nil {
		t.Fatalf("renderer.Finish() error = %v", err)
	}

	output := buffer.String()
	for _, pattern := range []string{
		"://LAYERLEAK",
		"Repository",
		"Findings     7 detected",
		"linux/amd64",
		"[################",
	} {
		if !strings.Contains(output, pattern) {
			t.Fatalf("output missing %q: %q", pattern, output)
		}
	}
}
