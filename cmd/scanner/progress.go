package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"git.tools.cloudfor.ge/andrew/layerleak/internal/jobs"
)

const layerLeakLogo = `
://      _        __   __ _____ ____  _     _____    _    _  __
://     | |      / /\  \ \ / /| ____|  _ \| |   | ____|  / \  | |/ /
://     | |     / /  \  \ V / |  _| | |_) | |   |  _|   / _ \ | ' /
://     | |___ / / /\ \  | |  | |___|  _ <| |___| |___ / ___ \| . \
://     |_____/_/ /  \_\ |_|  |_____|_| \_\_____|_____/_/   \_\_|\_\
://LAYERLEAK
`

const progressBlockLines = 8

type progressSnapshot struct {
	repository       string
	tagsCompleted    int
	tagsFailed       int
	tagsTotal        int
	targetsCompleted int
	targetsFailed    int
	targetsTotal     int
	findingsFound    int
	currentTag       string
	currentReference string
	currentManifest  string
	currentPlatform  string
	phase            string
	message          string
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

func (r *progressRenderer) UpdateFromJob(update jobs.ProgressUpdate) error {
	state := r.state
	state.repository = update.Repository
	state.tagsCompleted = update.TagsCompleted
	state.tagsFailed = update.TagsFailed
	state.tagsTotal = update.TagsTotal
	state.targetsCompleted = update.TargetsCompleted
	state.targetsFailed = update.TargetsFailed
	state.targetsTotal = update.TargetsTotal
	state.findingsFound = update.FindingsFound
	state.currentTag = update.CurrentTag
	state.currentReference = update.CurrentReference
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
	tagLabel := progressLabel(r.state.tagsCompleted, r.state.tagsTotal, r.state.tagsFailed, "waiting for tag enumeration")
	targetLabel := progressLabel(r.state.targetsCompleted, r.state.targetsTotal, r.state.targetsFailed, "waiting for target selection")
	progressCompleted, progressTotal := progressCounts(r.state)

	return []string{
		fmt.Sprintf("Repository   %s", defaultValue(r.state.repository, "unknown")),
		fmt.Sprintf("Tags         %s", tagLabel),
		fmt.Sprintf("Targets      %s", targetLabel),
		fmt.Sprintf("Phase        %s", defaultValue(r.state.phase, "Starting")),
		fmt.Sprintf("Status       %s", defaultValue(r.state.message, "Preparing scan")),
		fmt.Sprintf("Progress     %s", renderBar(progressCompleted, progressTotal, 32)),
		fmt.Sprintf("Findings     %d detected", r.state.findingsFound),
		fmt.Sprintf("Current      %s", currentTargetLabel(r.state)),
	}
}

func progressPhaseLabel(phase jobs.ProgressPhase) string {
	switch phase {
	case jobs.ProgressPhaseListingTags:
		return "Listing Tags"
	case jobs.ProgressPhaseResolvingTags:
		return "Resolving Tags"
	case jobs.ProgressPhaseScanning:
		return "Scanning"
	case jobs.ProgressPhaseTargetDone:
		return "Target Complete"
	case jobs.ProgressPhaseTargetFailed:
		return "Target Failed"
	case jobs.ProgressPhaseCompleted:
		return "Complete"
	default:
		return "Scanning"
	}
}

func currentTargetLabel(state progressSnapshot) string {
	if state.currentTag != "" && state.currentPlatform != "" && state.currentManifest != "" {
		return state.currentTag + " " + state.currentPlatform + " [" + shortDigest(state.currentManifest) + "]"
	}
	if state.currentTag != "" && state.currentReference != "" {
		return state.currentTag + " " + shortReference(state.currentReference)
	}
	if state.currentReference != "" && state.currentPlatform != "" && state.currentManifest != "" {
		return shortReference(state.currentReference) + " " + state.currentPlatform + " [" + shortDigest(state.currentManifest) + "]"
	}
	if state.currentPlatform != "" && state.currentManifest != "" {
		return state.currentPlatform + " [" + shortDigest(state.currentManifest) + "]"
	}
	if state.currentTag != "" {
		return state.currentTag
	}
	if state.currentReference != "" {
		return shortReference(state.currentReference)
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

func shortReference(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= 36 {
		return trimmed
	}
	return trimmed[:36] + "..."
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

func progressLabel(completed, total, failed int, waiting string) string {
	if total <= 0 {
		return waiting
	}
	return fmt.Sprintf("%d/%d complete, %d failed", completed, total, failed)
}

func progressCounts(state progressSnapshot) (int, int) {
	if state.targetsTotal > 0 {
		return state.targetsCompleted + state.targetsFailed, state.targetsTotal
	}
	if state.tagsTotal > 0 {
		return state.tagsCompleted + state.tagsFailed, state.tagsTotal
	}
	return 0, 0
}

func savedResultMessage(path string) string {
	if strings.TrimSpace(path) == "" {
		return "Saved findings result"
	}
	return "Saved " + filepath.Base(path)
}
