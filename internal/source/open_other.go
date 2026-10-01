//go:build !unix

package source

// nonBlockingOpenFlag is zero where opening a named pipe from the file system
// cannot block the way a Unix FIFO does.
const nonBlockingOpenFlag = 0
