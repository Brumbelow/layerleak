package layers

import (
	"bytes"
	"encoding/binary"
	"math"
)

// zip end-of-central-directory geometry, as archive/zip reads it.
const (
	zipDirectoryEndLen      = 22
	zipDirectory64LocLen    = 20
	zipDirectory64EndLen    = 56
	zipDirectoryHeaderLen   = 46
	zipMaxCommentLen        = 65535
	zipDirectoryEndSearch   = zipDirectoryEndLen + zipMaxCommentLen
	zipDirectoryEndSig      = "PK\x05\x06"
	zipDirectory64LocSig    = "PK\x06\x07"
	zipDirectory64EndSig    = "PK\x06\x06"
	zipDirectoryHeaderSig   = "PK\x01\x02"
	zipDirectoryEndRecords  = 10
	zipDirectoryEndSize     = 12
	zipDirectoryEndOffset   = 16
	zipDirectory64Records   = 32
	zipDirectory64Size      = 40
	zipDirectory64Offset    = 48
	zipDirectoryHeaderName  = 28
	zipDirectoryHeaderExtra = 30
	zipDirectoryHeaderNote  = 32
)

// zipDirectoryEntries reports how many central directory headers archive/zip
// would materialise for content, without allocating any: the larger of the
// count the end-of-central-directory record (or its zip64 successor) declares
// and the number of headers the directory region actually holds. The reader
// compares the declared count with the parsed one in 16 bits only, so a
// hostile archive can declare few entries and store many; counting the
// headers in place closes that gap. ok is false when no end record can be
// located, in which case archive/zip rejects the content before parsing
// anything.
func zipDirectoryEntries(content []byte) (entries int64, ok bool) {
	size := int64(len(content))
	end := zipFindDirectoryEnd(content)
	if end < 0 {
		return 0, false
	}
	records := int64(binary.LittleEndian.Uint16(content[end+zipDirectoryEndRecords:]))
	directorySize := int64(binary.LittleEndian.Uint32(content[end+zipDirectoryEndSize:]))
	directoryOffset := int64(binary.LittleEndian.Uint32(content[end+zipDirectoryEndOffset:]))
	directoryEnd := int64(end)
	if records == 0xffff || directorySize == 0xffffffff || directoryOffset == 0xffffffff {
		end64, found := zipFindDirectory64End(content, end)
		if found {
			directoryEnd = int64(end64)
			records64 := binary.LittleEndian.Uint64(content[end64+zipDirectory64Records:])
			size64 := binary.LittleEndian.Uint64(content[end64+zipDirectory64Size:])
			offset64 := binary.LittleEndian.Uint64(content[end64+zipDirectory64Offset:])
			if records64 > uint64(size) {
				// More entries than bytes: the directory cannot hold them, so
				// the declaration alone decides (capped to stay an int64).
				if records64 > math.MaxInt64 {
					return math.MaxInt64, true
				}
				return int64(records64), true
			}
			if size64 > uint64(size) || offset64 > uint64(size) {
				return 0, false
			}
			records, directorySize, directoryOffset = int64(records64), int64(size64), int64(offset64) //nolint:gosec // each value was checked above to be at most len(content)
		}
	}
	// archive/zip reads the directory from directoryEnd-directorySize, or from
	// directoryOffset when a header is found there; count from both so the
	// result bounds either choice.
	entries = records
	for _, start := range []int64{directoryEnd - directorySize, directoryOffset} {
		if start < 0 || start >= size {
			continue
		}
		if counted := zipCountDirectoryHeaders(content[start:]); counted > entries {
			entries = counted
		}
	}
	return entries, true
}

// zipFindDirectoryEnd returns the offset of the last end-of-central-directory
// record whose declared comment fits the content, searching back through the
// longest possible comment, or -1.
func zipFindDirectoryEnd(content []byte) int {
	stop := len(content) - zipDirectoryEndSearch
	if stop < 0 {
		stop = 0
	}
	for offset := len(content) - zipDirectoryEndLen; offset >= stop; offset-- {
		if string(content[offset:offset+4]) != zipDirectoryEndSig {
			continue
		}
		comment := int(binary.LittleEndian.Uint16(content[offset+zipDirectoryEndLen-2:]))
		if offset+zipDirectoryEndLen+comment <= len(content) {
			return offset
		}
	}
	return -1
}

// zipFindDirectory64End follows the zip64 locator that precedes the end record
// at end to the zip64 end-of-central-directory record, as archive/zip does.
func zipFindDirectory64End(content []byte, end int) (int, bool) {
	locator := end - zipDirectory64LocLen
	if locator < 0 || len(content) < zipDirectory64EndLen || string(content[locator:locator+4]) != zipDirectory64LocSig {
		// Content shorter than a zip64 end record cannot hold one; checking
		// first also keeps the bound below from wrapping.
		return 0, false
	}
	if binary.LittleEndian.Uint32(content[locator+4:]) != 0 || binary.LittleEndian.Uint32(content[locator+16:]) != 1 {
		// The archive spans several disks; the reader gives up on it.
		return 0, false
	}
	offset := binary.LittleEndian.Uint64(content[locator+8:])
	if offset > uint64(len(content)-zipDirectory64EndLen) { //nolint:gosec // len(content) >= zipDirectory64EndLen was checked above, so the difference is not negative
		return 0, false
	}
	end64 := int(offset) //nolint:gosec // offset is at most len(content)-zipDirectory64EndLen, so it fits an int
	if string(content[end64:end64+4]) != zipDirectory64EndSig {
		return 0, false
	}
	return end64, true
}

// zipCountDirectoryHeaders counts the consecutive, complete central directory
// headers at the start of region, which is how far archive/zip would parse.
func zipCountDirectoryHeaders(region []byte) int64 {
	var count int64
	for len(region) >= zipDirectoryHeaderLen && bytes.Equal(region[:4], []byte(zipDirectoryHeaderSig)) {
		variable := int(binary.LittleEndian.Uint16(region[zipDirectoryHeaderName:])) +
			int(binary.LittleEndian.Uint16(region[zipDirectoryHeaderExtra:])) +
			int(binary.LittleEndian.Uint16(region[zipDirectoryHeaderNote:]))
		if zipDirectoryHeaderLen+variable > len(region) {
			break
		}
		count++
		region = region[zipDirectoryHeaderLen+variable:]
	}
	return count
}
