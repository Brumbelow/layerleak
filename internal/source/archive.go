package source

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"unicode"

	"github.com/brumbelow/layerleak/v3/internal/limits"
)

// tarIndex is a read-only index of the regular files in a tar archive: for
// every entry the byte offset of its data and its size, so a blob can be
// served as a section of the archive file without extracting anything.
type tarIndex struct {
	path    string
	file    *os.File
	entries map[string]tarEntry
}

type tarEntry struct {
	offset int64
	size   int64
}

// errUnsafeArchivePath marks an archive whose entry names cannot be trusted.
var errUnsafeArchivePath = errors.New("unsafe archive entry path")

// openTarIndex indexes the archive at archivePath in one pass. Entry names
// are validated (no absolute paths, no `..` components, no control
// characters, bounded length) and an archive carrying one unsafe name is
// refused whole. Only regular files are indexed: symbolic links, hard links,
// directories and other types are skipped so a link is never followed. The
// pass stops with limits.KindLayerEntries when the archive has more than
// maxEntries entries, and each data section must lie inside the file.
func openTarIndex(archivePath string, maxEntries int) (*tarIndex, error) {
	file, err := os.Open(archivePath) //nolint:gosec // the archive path is the operator's command-line argument
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	index, err := indexTar(file, archivePath, maxEntries)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return index, nil
}

func indexTar(file *os.File, archivePath string, maxEntries int) (*tarIndex, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat archive: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("archive %s is not a regular file", archivePath)
	}
	archiveSize := info.Size()

	index := &tarIndex{path: archivePath, file: file, entries: make(map[string]tarEntry)}
	reader := tar.NewReader(file)
	count := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil && !errors.Is(err, tar.ErrInsecurePath) {
			return nil, fmt.Errorf("read archive %s: %w", archivePath, err)
		}
		count++
		if count > maxEntries {
			return nil, limits.NewExceeded(limits.KindLayerEntries, int64(maxEntries), "archive "+archivePath)
		}
		name, err := cleanArchivePath(header.Name)
		if err != nil {
			return nil, fmt.Errorf("archive %s: %w", archivePath, err)
		}
		if header.Typeflag != tar.TypeReg {
			// Links, directories, devices and sparse files are never served.
			continue
		}
		if header.Size < 0 {
			return nil, fmt.Errorf("archive %s: entry %s has a negative size", archivePath, name)
		}
		// The tar reader consumed exactly the header blocks, so the file is
		// positioned at the first data byte of this entry.
		offset, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("archive %s: locate entry %s: %w", archivePath, name, err)
		}
		if offset < 0 || header.Size > archiveSize-offset {
			return nil, fmt.Errorf("archive %s: entry %s extends past the end of the file", archivePath, name)
		}
		index.entries[name] = tarEntry{offset: offset, size: header.Size}
	}
	return index, nil
}

// cleanArchivePath validates an archive entry name and returns it as a clean
// slash path relative to the archive root.
func cleanArchivePath(name string) (string, error) {
	if len(name) > maxArchiveEntryPathBytes {
		return "", fmt.Errorf("%w: entry name longer than %d bytes", errUnsafeArchivePath, maxArchiveEntryPathBytes)
	}
	if name == "" {
		return "", fmt.Errorf("%w: empty entry name", errUnsafeArchivePath)
	}
	if strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar }) {
		return "", fmt.Errorf("%w: entry name contains control characters", errUnsafeArchivePath)
	}
	if strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("%w: entry name contains a backslash", errUnsafeArchivePath)
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%w: absolute entry name", errUnsafeArchivePath)
	}
	for _, component := range strings.Split(name, "/") {
		if component == ".." {
			return "", fmt.Errorf("%w: entry name contains a parent directory component", errUnsafeArchivePath)
		}
	}
	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == "" {
		return "", fmt.Errorf("%w: entry name is the archive root", errUnsafeArchivePath)
	}
	return cleaned, nil
}

// lookup returns the entry stored under a clean slash path.
func (t *tarIndex) lookup(name string) (tarEntry, bool) {
	entry, ok := t.entries[path.Clean(name)]
	return entry, ok
}

// open serves the entry as a reader over its section of the archive.
func (t *tarIndex) open(name string) (sizedReadCloser, error) {
	entry, ok := t.lookup(name)
	if !ok {
		return nil, fmt.Errorf("%s: %w", name, os.ErrNotExist)
	}
	return sectionReadCloser{io.NewSectionReader(t.file, entry.offset, entry.size)}, nil
}

// readAll reads a whole entry, bounded by maxBytes.
func (t *tarIndex) readAll(name string, maxBytes int64) ([]byte, error) {
	entry, ok := t.lookup(name)
	if !ok {
		return nil, fmt.Errorf("%s: %w", name, os.ErrNotExist)
	}
	if entry.size > maxBytes {
		return nil, limits.NewExceeded(limits.KindManifestBytes, maxBytes, name)
	}
	return readDocument(io.NewSectionReader(t.file, entry.offset, entry.size), maxBytes, name)
}

func (t *tarIndex) Close() error {
	return t.file.Close()
}
