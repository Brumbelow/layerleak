package layers

import (
	"bytes"
	"encoding/binary"
	"math"
)

// zip end-of-central-directory geometry, as archive/zip reads it.
const (
	zipDirectoryEndLen    = 22
	zipDirectory64LocLen  = 20
	zipDirectory64EndLen  = 56
	zipDirectoryHeaderLen = 46
	// zipDirectoryEndSearch is how far back from the end archive/zip looks
	// for the end record (readDirectoryEnd: the last 1 KiB, then the last
	// 65 KiB, which finds the same record when the first pass does).
	zipDirectoryEndSearch   = 65 * 1024
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
// headers in place closes that gap. ok is false only where archive/zip
// itself rejects the content before parsing any header (no end record in its
// search window, a comment running past the end, a zip64 directory larger
// than the content); callers refuse such content rather than parse it.
func zipDirectoryEntries(content []byte) (entries int64, ok bool) {
	end := zipFindDirectoryEnd(content)
	if end < 0 {
		return 0, false
	}
	directory := zipReadDirectoryEnd(content, end)
	if directory.records == 0xffff || directory.size == 0xffffffff || directory.offset == 0xffffffff {
		declared, valid, decided := directory.applyZip64(content, end)
		if decided {
			return declared, valid
		}
	}
	return directory.countEntries(content), true
}

// zipDirectory is the central directory geometry an end record declares:
// the entry count, the directory's size and offset, and where the record
// that declares them starts.
type zipDirectory struct {
	records int64
	size    int64
	offset  int64
	end     int64
}

// zipReadDirectoryEnd reads the geometry the end record at end declares.
func zipReadDirectoryEnd(content []byte, end int) zipDirectory {
	return zipDirectory{
		records: int64(binary.LittleEndian.Uint16(content[end+zipDirectoryEndRecords:])),
		size:    int64(binary.LittleEndian.Uint32(content[end+zipDirectoryEndSize:])),
		offset:  int64(binary.LittleEndian.Uint32(content[end+zipDirectoryEndOffset:])),
		end:     int64(end),
	}
}

// applyZip64 replaces the geometry with the zip64 end record's, when the
// locator before the end record at end leads to one. decided is true when
// the zip64 record alone settles zipDirectoryEntries' result (entries, ok).
func (d *zipDirectory) applyZip64(content []byte, end int) (entries int64, ok, decided bool) {
	end64, found := zipFindDirectory64End(content, end)
	if !found {
		return 0, false, false
	}
	size := int64(len(content))
	d.end = int64(end64)
	records64 := binary.LittleEndian.Uint64(content[end64+zipDirectory64Records:])
	size64 := binary.LittleEndian.Uint64(content[end64+zipDirectory64Size:])
	offset64 := binary.LittleEndian.Uint64(content[end64+zipDirectory64Offset:])
	if records64 > uint64(size) {
		// More entries than bytes: the directory cannot hold them, so
		// the declaration alone decides (capped to stay an int64).
		if records64 > math.MaxInt64 {
			return math.MaxInt64, true, true
		}
		return int64(records64), true, true
	}
	if size64 > uint64(size) || offset64 > math.MaxInt64 {
		// archive/zip rejects both: the directory would start before
		// the content, or its offset does not fit an int64. An offset
		// past the end is not rejected (the reader then reads the
		// directory from end64-size64), so it is not refused here.
		return 0, false, true
	}
	d.records, d.size, d.offset = int64(records64), int64(size64), int64(offset64) //nolint:gosec // records64 and size64 are at most len(content) and offset64 at most MaxInt64, checked above
	return 0, false, false
}

// countEntries is the larger of the declared entry count and the headers
// the directory region holds. archive/zip reads the directory from
// end-size, or from offset when a header is found there; count from both so
// the result bounds either choice.
func (d zipDirectory) countEntries(content []byte) int64 {
	size := int64(len(content))
	entries := d.records
	for _, start := range []int64{d.end - d.size, d.offset} {
		if start < 0 || start >= size {
			continue
		}
		if counted := zipCountDirectoryHeaders(content[start:]); counted > entries {
			entries = counted
		}
	}
	return entries
}

// zipFindDirectoryEnd returns the offset of the end-of-central-directory
// record archive/zip would use, or -1 where archive/zip finds none: the last
// signature within the final zipDirectoryEndSearch bytes, and only when its
// declared comment fits the content (an earlier record is never tried).
// Trailing bytes after the comment are allowed, as the reader allows them.
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
		if offset+zipDirectoryEndLen+comment > len(content) {
			return -1
		}
		return offset
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
