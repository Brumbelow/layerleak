//go:build !windows

package cli

import "testing"

func TestEnableVirtualTerminalIsANoOpOffWindows(t *testing.T) {
	if !enableVirtualTerminal(-1) || !enableVirtualTerminal(2) {
		t.Fatal("enableVirtualTerminal must report true on non-Windows platforms")
	}
}
