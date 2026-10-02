//go:build unix

package source

import "syscall"

// nonBlockingOpenFlag makes opening a FIFO return at once instead of waiting
// for a writer; it has no effect on reads of a regular file.
const nonBlockingOpenFlag = syscall.O_NONBLOCK
