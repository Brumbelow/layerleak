package limits

import (
	"math"
	"testing"
)

func TestOverflowProbeLimit(t *testing.T) {
	if got := OverflowProbeLimit(10); got != 11 {
		t.Fatalf("OverflowProbeLimit(10) = %d", got)
	}
	if got := OverflowProbeLimit(math.MaxInt64); got != math.MaxInt64 {
		t.Fatalf("OverflowProbeLimit(MaxInt64) = %d", got)
	}
}
