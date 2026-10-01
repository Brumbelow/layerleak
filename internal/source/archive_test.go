package source

import (
	"archive/tar"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// The archive index records the data offset of each entry from the file
// position after the tar reader parsed its header blocks. PAX and GNU long
// name headers occupy extra blocks, so entries after and with long names must
// still read back exactly.
func TestTarIndexOffsetsSurviveLongNameHeaders(t *testing.T) {
	longName := strings.Repeat("directory/", 15) + "entry.json" // > 100 bytes forces a PAX header
	files := []tarFile{
		{name: "first", body: []byte("first body")},
		{name: longName, body: []byte(strings.Repeat("long body ", 100))},
		{name: "last", body: []byte("")},
		{name: "dir", typeflag: tar.TypeDir},
		{name: "after-dir", body: []byte("after")},
	}
	archive := filepath.Join(t.TempDir(), "long.tar")
	writeFile(t, archive, tarBytes(t, files))

	index, err := openTarIndex(archive, DefaultMaxArchiveEntries)
	if err != nil {
		t.Fatalf("openTarIndex() error = %v", err)
	}
	defer func() { _ = index.Close() }()
	if len(index.entries) != 4 {
		t.Fatalf("indexed %d entries, want 4 regular files", len(index.entries))
	}
	for _, file := range files {
		if file.typeflag == tar.TypeDir {
			continue
		}
		reader, err := index.open(file.name)
		if err != nil {
			t.Fatalf("open(%s) error = %v", file.name, err)
		}
		body, err := io.ReadAll(reader)
		if err != nil || string(body) != string(file.body) || reader.Size() != int64(len(file.body)) {
			t.Fatalf("open(%s) = %q (size %d), %v; want %q", file.name, body, reader.Size(), err, file.body)
		}
	}
	if _, ok := index.lookup("./first"); !ok {
		t.Fatal("lookup ignores a ./ prefix")
	}
}
