package findings

import (
	"strings"

	"github.com/brumbelow/layerleak/internal/detectionpolicy"
	"github.com/brumbelow/layerleak/internal/detectors"
)

func Classify(input Input, match detectors.Match) (Disposition, DispositionReason) {
	reason := detectionpolicy.ExampleReason(input.FilePath, input.Key, matchLine(input.Content, match.Start, match.End), match.Value)
	if reason == detectionpolicy.ReasonNone {
		return DispositionActionable, DispositionReasonNone
	}

	return DispositionExample, mapDispositionReason(reason)
}

func matchLine(content string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end < start {
		end = start
	}
	if end > len(content) {
		end = len(content)
	}

	lineStart := strings.LastIndex(content[:start], "\n")
	if lineStart < 0 {
		lineStart = 0
	} else {
		lineStart++
	}
	lineEnd := strings.Index(content[end:], "\n")
	if lineEnd < 0 {
		lineEnd = len(content)
	} else {
		lineEnd = end + lineEnd
	}

	return content[lineStart:lineEnd]
}

func mapDispositionReason(reason string) DispositionReason {
	switch reason {
	case detectionpolicy.ReasonTestPath:
		return DispositionReasonTestPath
	case detectionpolicy.ReasonExamplePath:
		return DispositionReasonExamplePath
	case detectionpolicy.ReasonPlaceholderMarker:
		return DispositionReasonPlaceholderMarker
	case detectionpolicy.ReasonReservedHost:
		return DispositionReasonReservedHost
	case detectionpolicy.ReasonKnownDummyValue:
		return DispositionReasonKnownDummyValue
	default:
		return DispositionReasonNone
	}
}
