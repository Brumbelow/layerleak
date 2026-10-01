//go:build windows

package cli

import "golang.org/x/sys/windows"

// enableVirtualTerminal switches the Windows console attached to fd into
// virtual-terminal processing so the cursor movements of the dynamic progress
// block render instead of printing as garbage. It reports false when the
// console refuses (for example on consoles older than Windows 10 1511), and
// the caller then falls back to the plain renderer.
func enableVirtualTerminal(fd int) bool {
	handle := windows.Handle(fd)
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
