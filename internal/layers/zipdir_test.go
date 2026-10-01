package layers

import (
	"encoding/binary"
	"testing"
)

// A zip64 locator in content too short to hold a zip64 end record must be
// rejected without slicing out of range.
func TestZipDirectoryEntriesShortZip64Locator(t *testing.T) {
	for size := zipDirectoryEndLen + zipDirectory64LocLen; size < zipDirectory64EndLen+zipDirectory64LocLen+zipDirectoryEndLen; size++ {
		content := make([]byte, size)
		end := size - zipDirectoryEndLen
		copy(content[end:], zipDirectoryEndSig)
		binary.LittleEndian.PutUint16(content[end+zipDirectoryEndRecords:], 0xffff)
		locator := end - zipDirectory64LocLen
		copy(content[locator:], zipDirectory64LocSig)
		binary.LittleEndian.PutUint32(content[locator+16:], 1)
		binary.LittleEndian.PutUint64(content[locator+8:], 0)
		// The zip64 record cannot exist in so few bytes, so the 16-bit
		// declaration (0xffff) is all there is to go on; the point is that
		// nothing slices out of range.
		entries, ok := zipDirectoryEntries(content)
		if !ok || entries != 0xffff {
			t.Fatalf("size %d: entries = %d, ok = %t", size, entries, ok)
		}
	}
}

// FuzzZipDirectoryEntries checks that the pre-parse directory count never
// panics and never reports a negative count, whatever the bytes are.
func FuzzZipDirectoryEntries(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte(zipDirectoryEndSig + "\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00"))
	short := make([]byte, 48)
	copy(short[26:], zipDirectoryEndSig)
	copy(short[6:], zipDirectory64LocSig)
	f.Add(short)
	f.Fuzz(func(t *testing.T, content []byte) {
		if entries, _ := zipDirectoryEntries(content); entries < 0 {
			t.Fatalf("entries = %d", entries)
		}
	})
}
