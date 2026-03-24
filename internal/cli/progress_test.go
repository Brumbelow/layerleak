package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/internal/jobs"
	"github.com/brumbelow/layerleak/internal/manifest"
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

func TestProgressRendererClampsDynamicLinesToTerminalWidth(t *testing.T) {
	var buffer bytes.Buffer
	renderer := newProgressRenderer(&buffer)
	renderer.dynamic = true
	renderer.widthFn = func() int { return 40 }
	renderer.state = progressSnapshot{
		repository:       "library/app",
		tagsCompleted:    951,
		tagsTotal:        951,
		targetsFailed:    71,
		targetsTotal:     948,
		findingsFound:    0,
		phase:            "Target Failed",
		message:          "apply layer sha256:18ec5c45ed12cb22d06f27e5a82e3cbadd5bfe9ef526f430b71d9646d70ec9a6: malformed gzip stream while scanning layer data",
		currentReference: "docker.io/dynatrace/dynatrace-operator@sha256:18ec5c45ed12cb22d06f27e5a82e3cbadd5bfe9ef526f430b71d9646d70ec9a6",
	}

	lines := renderer.buildLines(renderer.renderLineWidth())
	if len(lines) != progressBlockLines {
		t.Fatalf("len(lines) = %d", len(lines))
	}

	for _, line := range lines {
		if strings.ContainsAny(line, "\r\n") {
			t.Fatalf("line contains newline characters: %q", line)
		}
		if len([]rune(line)) > 39 {
			t.Fatalf("line length = %d, want <= 39: %q", len([]rune(line)), line)
		}
	}

	if !strings.HasSuffix(lines[4], "...") {
		t.Fatalf("status line was not truncated: %q", lines[4])
	}
}

func TestProgressRendererSanitizesControlCharacters(t *testing.T) {
	var buffer bytes.Buffer
	renderer := newProgressRenderer(&buffer)
	renderer.state = progressSnapshot{
		repository: "library/app",
		phase:      "Target Failed",
		message:    "apply layer sha256:deadbeef\nbad entry\r\nwith\tcontrols",
	}

	lines := renderer.buildLines(0)
	if len(lines) != progressBlockLines {
		t.Fatalf("len(lines) = %d", len(lines))
	}

	statusLine := lines[4]
	if strings.ContainsAny(statusLine, "\r\n\t") {
		t.Fatalf("status line contains control characters: %q", statusLine)
	}
	if !strings.Contains(statusLine, "apply layer sha256:deadbeef bad entry with controls") {
		t.Fatalf("status line not sanitized as expected: %q", statusLine)
	}
}
