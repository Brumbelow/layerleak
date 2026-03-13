package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/scanner"
)

const layerLeakLogo = `
://      _        __   __ _____ ____  _     _____    _    _  __
://     | |      / /\  \ \ / /| ____|  _ \| |   | ____|  / \  | |/ /
://     | |     / /  \  \ V / |  _| | |_) | |   |  _|   / _ \ | ' /
://     | |___ / / /\ \  | |  | |___|  _ <| |___| |___ / ___ \| . \
://     |_____/_/ /  \_\ |_|  |_____|_| \_\_____|_____/_/   \_\_|\_\
://LAYERLEAK
`

const progressBlockLines = 6

type progressSnapshot struct {
	repository            string
	repositoriesCompleted int
	repositoriesTotal     int
	manifestCompleted     int
	manifestFailed        int
	manifestTotal         int
	findingsFound         int
	currentManifest       string
	currentPlatform       string
	phase                 string
	message               string
}

type progressRenderer struct {
	out      io.Writer
	dynamic  bool
	started  bool
	rendered bool
	state    progressSnapshot
}

func newProgressRenderer(out io.Writer) *progressRenderer {
	return &progressRenderer{
		out:     out,
		dynamic: isTerminalWriter(out),
	}
}

func (r *progressRenderer) Start(state progressSnapshot) error {
	if r.started {
		return nil
	}
	r.started = true
	r.state = state
	if _, err := fmt.Fprint(r.out, layerLeakLogo); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(r.out); err != nil {
		return err
	}
	return r.render()
}

func (r *progressRenderer) UpdateFromScan(update scanner.ProgressUpdate) error {
	state := r.state
	state.repository = update.Repository
	state.repositoriesCompleted = update.RepositoriesCompleted
	state.repositoriesTotal = update.RepositoriesTotal
	state.manifestCompleted = update.ManifestCompleted
	state.manifestFailed = update.ManifestFailed
	state.manifestTotal = update.ManifestTotal
	state.findingsFound = update.FindingsFound
	state.currentManifest = update.CurrentManifestDigest
	state.currentPlatform = update.CurrentPlatform.String()
	state.phase = progressPhaseLabel(update.Phase)
	state.message = update.Message
	return r.Update(state)
}

func (r *progressRenderer) Update(state progressSnapshot) error {
	if !r.started {
		return r.Start(state)
	}
	r.state = state
	return r.render()
}

func (r *progressRenderer) Finish() error {
	if !r.started {
		return nil
	}
	_, err := fmt.Fprintln(r.out)
	return err
}

func (r *progressRenderer) render() error {
	lines := r.buildLines()
	if r.dynamic && r.rendered {
		if _, err := fmt.Fprintf(r.out, "\x1b[%dA", progressBlockLines); err != nil {
			return err
		}
	}
	for _, line := range lines {
		if r.dynamic {
			if _, err := fmt.Fprint(r.out, "\r\x1b[2K"); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(r.out, line); err != nil {
			return err
		}
	}
	r.rendered = true
	return nil
}

func (r *progressRenderer) buildLines() []string {
	repoTotal := r.state.repositoriesTotal
	if repoTotal <= 0 {
		repoTotal = 1
	}
	manifestLabel := fmt.Sprintf("%d/%d complete, %d failed", r.state.manifestCompleted, maxInt(r.state.manifestTotal, 0), r.state.manifestFailed)
	if r.state.manifestTotal <= 0 {
		manifestLabel = "waiting for manifest selection"
	}

	return []string{
		fmt.Sprintf("Repository   [%d/%d] %s", r.state.repositoriesCompleted, repoTotal, defaultValue(r.state.repository, "unknown")),
		fmt.Sprintf("Phase        %s", defaultValue(r.state.phase, "Starting")),
		fmt.Sprintf("Status       %s", defaultValue(r.state.message, "Preparing scan")),
		fmt.Sprintf("Progress     %s %s", renderBar(r.state.manifestCompleted+r.state.manifestFailed, r.state.manifestTotal, 32), manifestLabel),
		fmt.Sprintf("Findings     %d detected", r.state.findingsFound),
		fmt.Sprintf("Current      %s", currentTargetLabel(r.state)),
	}
}

func progressPhaseLabel(phase scanner.ProgressPhase) string {
	switch phase {
	case scanner.ProgressPhaseResolvingReference:
		return "Resolving Reference"
	case scanner.ProgressPhaseSelectingManifests:
		return "Selecting Manifests"
	case scanner.ProgressPhaseManifestStarted:
		return "Scanning Manifest"
	case scanner.ProgressPhaseManifestCompleted:
		return "Manifest Complete"
	case scanner.ProgressPhaseManifestFailed:
		return "Manifest Failed"
	case scanner.ProgressPhaseCompleted:
		return "Complete"
	default:
		return "Scanning"
	}
}

func currentTargetLabel(state progressSnapshot) string {
	if state.currentPlatform != "" && state.currentManifest != "" {
		return state.currentPlatform + " [" + shortDigest(state.currentManifest) + "]"
	}
	if state.currentPlatform != "" {
		return state.currentPlatform
	}
	if state.currentManifest != "" {
		return shortDigest(state.currentManifest)
	}
	return "waiting"
}

func shortDigest(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= 20 {
		return trimmed
	}
	return trimmed[:20] + "..."
}

func renderBar(completed, total, width int) string {
	if width <= 0 {
		width = 20
	}
	if total <= 0 {
		return "[" + strings.Repeat("-", width) + "]"
	}
	if completed < 0 {
		completed = 0
	}
	if completed > total {
		completed = total
	}
	filled := int(float64(completed) / float64(total) * float64(width))
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", width-filled) + "]"
}

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func isTerminalWriter(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func savedResultMessage(path string) string {
	if strings.TrimSpace(path) == "" {
		return "Saved findings result"
	}
	return "Saved " + filepath.Base(path)
}
