//go:build !windows

package cli

// enableVirtualTerminal reports whether the terminal attached to fd can render
// the dynamic progress block. Unix terminals interpret ANSI sequences natively,
// so nothing has to be switched on.
func enableVirtualTerminal(int) bool {
	return true
}
