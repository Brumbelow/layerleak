package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/brumbelow/layerleak/internal/jobs"
	"golang.org/x/term"
)

const layerLeakLogo = `

       ██╗    ██╗
██╗   ██╔╝   ██╔╝
╚═╝  ██╔╝   ██╔╝
██╗ ██╔╝   ██╔╝
╚═╝██╔╝   ██╔╝
   ╚═╝    ╚═╝

██╗      █████╗ ██╗   ██╗███████╗██████╗ ██╗     ███████╗ █████╗ ██╗  ██╗
██║     ██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗██║     ██╔════╝██╔══██╗██║ ██╔╝
██║     ███████║ ╚████╔╝ █████╗  ██████╔╝██║     █████╗  ███████║█████╔╝
██║     ██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██╗██║     ██╔══╝  ██╔══██║██╔═██╗
███████╗██║  ██║   ██║   ███████╗██║  ██║███████╗███████╗██║  ██║██║  ██╗
╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
                                                         
`

const progressBlockLines = 8
const defaultProgressWidth = 80

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
	out        io.Writer
	dynamic    bool
	started    bool
	rendered   bool
	terminalFD int
	widthFn    func() int
	state      progressSnapshot
}

func newProgressRenderer(out io.Writer) *progressRenderer {
	terminalFD, ok := terminalFileDescriptor(out)
	if !ok {
		terminalFD = -1
	}

	renderer := &progressRenderer{
		out:        out,
		dynamic:    terminalFD >= 0 && term.IsTerminal(terminalFD),
		terminalFD: terminalFD,
	}
	renderer.widthFn = renderer.currentWidth
	return renderer
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
	lines := r.buildLines(r.renderLineWidth())
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

func (r *progressRenderer) buildLines(maxWidth int) []string {
	tagLabel := progressLabel(r.state.tagsCompleted, r.state.tagsTotal, r.state.tagsFailed, "waiting for tag enumeration")
	targetLabel := progressLabel(r.state.targetsCompleted, r.state.targetsTotal, r.state.targetsFailed, "waiting for target selection")
	progressCompleted, progressTotal := progressCounts(r.state)

	return []string{
		renderProgressLine("Repository", progressValue(r.state.repository, "unknown"), maxWidth),
		renderProgressLine("Tags", progressValue(tagLabel, "waiting for tag enumeration"), maxWidth),
		renderProgressLine("Targets", progressValue(targetLabel, "waiting for target selection"), maxWidth),
		renderProgressLine("Phase", progressValue(r.state.phase, "Starting"), maxWidth),
		renderProgressLine("Status", progressValue(r.state.message, "Preparing scan"), maxWidth),
		renderProgressLine("Progress", renderBar(progressCompleted, progressTotal, 32), maxWidth),
		renderProgressLine("Findings", fmt.Sprintf("%d detected", r.state.findingsFound), maxWidth),
		renderProgressLine("Current", progressValue(currentTargetLabel(r.state), "waiting"), maxWidth),
	}
}

func (r *progressRenderer) currentWidth() int {
	if r.terminalFD >= 0 {
		if width, _, err := term.GetSize(r.terminalFD); err == nil && width > 0 {
			return width
		}
	}
	if width := widthFromEnv("COLUMNS"); width > 0 {
		return width
	}
	return defaultProgressWidth
}

func (r *progressRenderer) renderLineWidth() int {
	if !r.dynamic {
		return 0
	}
	width := defaultProgressWidth
	if r.widthFn != nil {
		width = r.widthFn()
	}
	if width <= 0 {
		width = defaultProgressWidth
	}
	if width > 1 {
		return width - 1
	}
	return width
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

func terminalFileDescriptor(out io.Writer) (int, bool) {
	file, ok := out.(*os.File)
	if !ok {
		return 0, false
	}
	return int(file.Fd()), true
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

func renderProgressLine(label, value string, maxWidth int) string {
	line := fmt.Sprintf("%-12s %s", label, sanitizeProgressValue(value))
	return clampProgressLine(line, maxWidth)
}

func progressValue(value, fallback string) string {
	sanitized := sanitizeProgressValue(value)
	if sanitized == "" {
		return fallback
	}
	return sanitized
}

func sanitizeProgressValue(value string) string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
	return strings.Join(fields, " ")
}

func clampProgressLine(line string, maxWidth int) string {
	if maxWidth <= 0 {
		return line
	}

	runes := []rune(line)
	if len(runes) <= maxWidth {
		return line
	}

	if maxWidth <= 3 {
		return strings.Repeat(".", maxWidth)
	}

	return string(runes[:maxWidth-3]) + "..."
}

func widthFromEnv(key string) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return 0
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0
	}

	return parsed
}
