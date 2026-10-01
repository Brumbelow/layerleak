package layers

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// encodeUTF16 renders text as UTF-16 in the given byte order, optionally
// preceded by a byte-order mark.
func encodeUTF16(t testing.TB, text string, order binary.ByteOrder, bom bool) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if bom {
		if err := binary.Write(&buffer, order, uint16(0xFEFF)); err != nil {
			t.Fatalf("write BOM: %v", err)
		}
	}
	for _, unit := range utf16.Encode([]rune(text)) {
		if err := binary.Write(&buffer, order, unit); err != nil {
			t.Fatalf("write code unit: %v", err)
		}
	}
	return buffer.Bytes()
}

func TestDetectUTF16(t *testing.T) {
	ascii := "token = ghp_000000000000000000000000000000000000\r\n"
	tests := []struct {
		name     string
		content  []byte
		encoding TextEncoding
		bom      int
	}{
		{name: "LE with BOM", content: encodeUTF16(t, ascii, binary.LittleEndian, true), encoding: TextEncodingUTF16LE, bom: 2},
		{name: "BE with BOM", content: encodeUTF16(t, ascii, binary.BigEndian, true), encoding: TextEncodingUTF16BE, bom: 2},
		{name: "LE without BOM", content: encodeUTF16(t, ascii, binary.LittleEndian, false), encoding: TextEncodingUTF16LE},
		{name: "BE without BOM", content: encodeUTF16(t, ascii, binary.BigEndian, false), encoding: TextEncodingUTF16BE},
		{name: "UTF-8 text", content: []byte(ascii)},
		{name: "empty", content: nil},
		{name: "too short to judge", content: encodeUTF16(t, "abc", binary.LittleEndian, false)},
		{name: "NUL code unit", content: append(encodeUTF16(t, "abcd", binary.LittleEndian, false), 0, 0, 'e', 0)},
		{name: "binary with zero bytes", content: []byte{0x7f, 0, 0x01, 0, 0x02, 0, 0x03, 0, 0x04, 0}},
		{name: "ELF-like", content: []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoding, bom := detectUTF16(tc.content)
			if encoding != tc.encoding || bom != tc.bom {
				t.Fatalf("detectUTF16() = (%q, %d), want (%q, %d)", encoding, bom, tc.encoding, tc.bom)
			}
		})
	}
}

func TestTranscodeUTF16(t *testing.T) {
	text := "SECRET=ghp_000000000000000000000000000000000000\nname=Zoë 🔑\n"
	for _, tc := range []struct {
		name     string
		order    binary.ByteOrder
		encoding TextEncoding
	}{
		{name: "LE", order: binary.LittleEndian, encoding: TextEncodingUTF16LE},
		{name: "BE", order: binary.BigEndian, encoding: TextEncodingUTF16BE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := encodeUTF16(t, text, tc.order, true)
			decoded, ok := transcodeUTF16(content, tc.encoding, 2, 1<<20)
			if !ok || string(decoded) != text {
				t.Fatalf("transcodeUTF16() = (%q, %v), want %q", decoded, ok, text)
			}
			if _, ok := transcodeUTF16(content, tc.encoding, 2, int64(len(text))-1); ok {
				t.Fatal("transcodeUTF16() accepted a decoded size above the limit")
			}
		})
	}

	t.Run("odd trailing byte and lone surrogate become U+FFFD", func(t *testing.T) {
		content := append(encodeUTF16(t, "ab", binary.LittleEndian, false), 0x00, 0xD8, 'c')
		decoded, ok := transcodeUTF16(content, TextEncodingUTF16LE, 0, 1<<20)
		if !ok || string(decoded) != "ab��" {
			t.Fatalf("transcodeUTF16() = (%q, %v)", decoded, ok)
		}
	})
}

func TestReplayTranscodesUTF16TextBeforeClassification(t *testing.T) {
	secret := "GITHUB_TOKEN=ghp_000000000000000000000000000000000000\n"
	layer := gzipLayer(t, []tarEntry{
		{name: "app/le-bom.env", body: string(encodeUTF16(t, secret, binary.LittleEndian, true))},
		{name: "app/be-bom.env", body: string(encodeUTF16(t, secret, binary.BigEndian, true))},
		{name: "app/le.ps1", body: string(encodeUTF16(t, "$token = 'ghp_000000000000000000000000000000000000'\r\n", binary.LittleEndian, false))},
		{name: "app/utf8.env", body: secret},
		{name: "app/binary.bin", body: "\x00\x01\x02\x03binary"},
		{name: "app/hard.env", typeflag: tar.TypeLink, linkname: "app/le-bom.env"},
	})
	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:utf16", body: layer}}, ReplayOptions{MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	byPath := make(map[string]Artifact)
	for _, artifact := range result.FinalFiles {
		byPath[artifact.Path] = artifact
	}
	for _, path := range []string{"app/le-bom.env", "app/be-bom.env", "app/hard.env"} {
		artifact := byPath[path]
		if !artifact.Scannable || artifact.ContentClass != ContentClassText || string(artifact.Content) != secret {
			t.Fatalf("%s = %+v, want scannable UTF-8 text %q", path, artifact, secret)
		}
	}
	if byPath["app/le-bom.env"].SourceEncoding != TextEncodingUTF16LE || byPath["app/be-bom.env"].SourceEncoding != TextEncodingUTF16BE {
		t.Fatalf("source encodings = %q / %q", byPath["app/le-bom.env"].SourceEncoding, byPath["app/be-bom.env"].SourceEncoding)
	}
	if ps1 := byPath["app/le.ps1"]; !ps1.Scannable || ps1.SourceEncoding != TextEncodingUTF16LE || !strings.HasPrefix(string(ps1.Content), "$token = 'ghp_") {
		t.Fatalf("app/le.ps1 = %+v", ps1)
	}
	if utf8 := byPath["app/utf8.env"]; utf8.SourceEncoding != "" || string(utf8.Content) != secret {
		t.Fatalf("app/utf8.env = %+v", utf8)
	}
	if bin := byPath["app/binary.bin"]; bin.Scannable || bin.ContentClass != ContentClassBinaryNUL {
		t.Fatalf("app/binary.bin = %+v", bin)
	}
	// Transcoded files count as scanned, never as binary exclusions; the
	// hardlink to a transcoded file counts once more.
	want := Coverage{LayersSeen: 1, LayersCompleted: 1, FilesSeen: 6, FilesScanned: 5, FilesExcludedBinary: 1, FilesTranscodedUTF16: 4}
	got := result.Coverage
	got.ExpandedBytes, got.RetainedBytes = 0, 0
	if got != want {
		t.Fatalf("Coverage = %+v, want %+v", got, want)
	}
	// Retention accounts for the transcoded (shorter) content, not the stored size.
	if recomputed := retainedForResult(result); recomputed != result.Coverage.RetainedBytes {
		t.Fatalf("RetainedBytes = %d, recomputed %d", result.Coverage.RetainedBytes, recomputed)
	}
}

func TestReplayBoundsTranscodedUTF16ByDecodedSize(t *testing.T) {
	// 300 CJK characters: 600 UTF-16 bytes (plus BOM) but 900 UTF-8 bytes.
	text := strings.Repeat("密", 300)
	content := encodeUTF16(t, text, binary.LittleEndian, true)
	if len(content) > 700 {
		t.Fatalf("fixture is %d bytes", len(content))
	}
	layer := gzipLayer(t, []tarEntry{{name: "app/wide.txt", body: string(content)}})
	result, err := replayTestLayers(t, []testLayer{{digest: "sha256:wide", body: layer}}, ReplayOptions{MaxFileBytes: 800})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(result.FinalFiles) != 1 {
		t.Fatalf("FinalFiles = %+v", result.FinalFiles)
	}
	artifact := result.FinalFiles[0]
	if artifact.Scannable || artifact.ContentClass != ContentClassOversize || artifact.Content != nil || artifact.SourceEncoding != "" {
		t.Fatalf("artifact = %+v, want oversize without content", artifact)
	}
	if result.Coverage.FilesSkippedOversize != 1 || result.Coverage.FilesTranscodedUTF16 != 0 {
		t.Fatalf("Coverage = %+v", result.Coverage)
	}

	// The same file fits once the limit covers its UTF-8 form.
	result, err = replayTestLayers(t, []testLayer{{digest: "sha256:wide", body: layer}}, ReplayOptions{MaxFileBytes: 900})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if artifact := result.FinalFiles[0]; !artifact.Scannable || string(artifact.Content) != text {
		t.Fatalf("artifact = %+v", artifact)
	}
}

func retainedForResult(result ReplayResult) int64 {
	var total int64
	seenDirectories := make(map[string]struct{})
	for _, artifact := range result.FinalFiles {
		total += retainedFinalArtifactBytes(artifact)
		for directory := parentPath(artifact.Path); directory != ""; directory = parentPath(directory) {
			if _, ok := seenDirectories[directory]; ok {
				break
			}
			seenDirectories[directory] = struct{}{}
			total += retainedMapStringBytes(directory)
		}
	}
	for _, artifact := range result.DeletedArtifacts {
		total += retainedDeletedArtifactBytes(artifact)
	}
	return total
}
