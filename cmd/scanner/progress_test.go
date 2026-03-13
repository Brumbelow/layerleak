package main

import (
	"bytes"
	"strings"
	"testing"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/jobs"
	"git.tools.cloudfor.ge/andrew/layerleak/internal/manifest"
)

func TestProgressRendererRendersLogoAndStatusBlock(t *testing.T) {
	var buffer bytes.Buffer
	renderer := newProgressRenderer(&buffer)

	if err := renderer.Start(progressSnapshot{
		repository: "library/app",
		phase:      "Starting",
		message:    "Preparing scan",
	}); err != nil {
		t.Fatalf("renderer.Start() error = %v", err)
	}
	if err := renderer.UpdateFromJob(jobs.ProgressUpdate{
		Phase:                 jobs.ProgressPhaseScanning,
		Repository:            "library/app",
		TagsCompleted:         3,
		TagsTotal:             5,
		TargetsCompleted:      1,
		TargetsTotal:          2,
		FindingsFound:         7,
		CurrentTag:            "latest",
		CurrentReference:      "docker.io/library/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CurrentPlatform:       manifest.Platform{OS: "linux", Architecture: "amd64"},
		CurrentManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Message:               "Scanning linux/amd64",
	}); err != nil {
		t.Fatalf("renderer.UpdateFromJob() error = %v", err)
	}
	if err := renderer.Finish(); err != nil {
		t.Fatalf("renderer.Finish() error = %v", err)
	}

	output := buffer.String()
	for _, pattern := range []string{
		"://LAYERLEAK",
		"Repository",
		"Tags",
		"Targets",
		"Findings     7 detected",
		"latest",
		"linux/amd64",
		"[################",
	} {
		if !strings.Contains(output, pattern) {
			t.Fatalf("output missing %q: %q", pattern, output)
		}
	}
}
