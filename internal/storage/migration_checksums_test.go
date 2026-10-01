package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// shippedMigrationChecksums freezes every file under migrations/. The ledger
// stores the SHA-256 of each 000N.up.sql and validateAppliedMigrations rejects
// any mismatch with "checksum changed" and no override, so a byte-level edit
// to a released file (whitespace cleanup, a license header, a formatter pass,
// a CRLF checkout used to build an image) would make RunMigrations and
// therefore every API startup fail against every existing database. The down
// files are frozen too because operators run them by hand. New behaviour goes
// in a new numbered pair; add its digests here when you add the files.
var shippedMigrationChecksums = map[string]string{
	"0001_initial.up.sql":                       "cefae744e62b9b052f0207507067d95e85a273dd4a4e3ab565b48ac7fdcd5f43",
	"0001_initial.down.sql":                     "debcf7a10f738dfb973624fb16ef47d0b665a808b88c278ec5fe7b68a17f79f4",
	"0002_finding_occurrence_metadata.up.sql":   "53721c24c993d360b88b3cf3891e0f9aca8083c403d9d8f67ecef484775007d5",
	"0002_finding_occurrence_metadata.down.sql": "0b16a59101d1d2455d0baf02e20993ff34ad374c7f34d67985b0aa1b789f3588",
	"0003_scan_runs.up.sql":                     "05bdabd562a6aa6b01c8ae52422903e035f0322d71b46052b3f6b5e2bc46cd0c",
	"0003_scan_runs.down.sql":                   "cf519ff2a05470744e743ede2074ccf80d36f335b067becaf0d3d3e3e8567d24",
	"0004_storage_hardening.up.sql":             "16e385fdff86018a6a69759a76753531ad55c0210df1e2c23bb9e6ddde426f65",
	"0004_storage_hardening.down.sql":           "3436dac5de16e0b3399ed4a48b89fe49f1a247d76b64e50e5822626cf33530cc",
}

// verifyShippedMigrationChecksums compares every .sql file in directory with
// the frozen digests and reports every difference at once.
func verifyShippedMigrationChecksums(directory string, expected map[string]string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	var problems []string
	seen := make(map[string]bool, len(expected))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		actual := hex.EncodeToString(sum[:])
		want, known := expected[entry.Name()]
		seen[entry.Name()] = true
		switch {
		case !known:
			problems = append(problems, fmt.Sprintf("%s is not in the frozen list; add its sha256 %s when shipping a new migration", entry.Name(), actual))
		case want != actual:
			hint := ""
			if strings.Contains(string(body), "\r\n") {
				hint = " (the file contains CRLF line endings; migrations must be checked out with LF, see .gitattributes)"
			}
			problems = append(problems, fmt.Sprintf("%s changed: sha256 %s, frozen %s%s; released migration files are immutable because the ledger pins their checksum, put new behaviour in a new numbered file", entry.Name(), actual, want, hint))
		}
	}
	for name := range expected {
		if !seen[name] {
			problems = append(problems, fmt.Sprintf("%s is missing from %s", name, directory))
		}
	}
	slices.Sort(problems)
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "\n"))
	}
	return nil
}

func TestShippedMigrationChecksumsAreFrozen(t *testing.T) {
	directory := filepath.Join(repoRoot(t), "migrations")
	if err := verifyShippedMigrationChecksums(directory, shippedMigrationChecksums); err != nil {
		t.Fatalf("shipped migration files drifted:\n%v", err)
	}
	// The up-file digests are exactly what loadMigrationFiles will record in
	// the ledger, so the guard and the runtime agree byte for byte.
	files, err := loadMigrationFiles(directory)
	if err != nil {
		t.Fatalf("loadMigrationFiles() error = %v", err)
	}
	if len(files) != currentMigrationCount {
		t.Fatalf("len(files) = %d", len(files))
	}
	for _, file := range files {
		if want := shippedMigrationChecksums[file.Name+".up.sql"]; file.Checksum != want {
			t.Fatalf("%s ledger checksum %s does not match the frozen digest %s", file.Name, file.Checksum, want)
		}
	}
}

func TestVerifyShippedMigrationChecksumsDetectsDrift(t *testing.T) {
	source := filepath.Join(repoRoot(t), "migrations")
	directory := t.TempDir()
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		switch entry.Name() {
		case "0001_initial.up.sql":
			body = append(body, '\n') // a trailing-newline cleanup
		case "0004_storage_hardening.up.sql":
			body = []byte(strings.ReplaceAll(string(body), "\n", "\r\n")) // a CRLF checkout
		case "0003_scan_runs.down.sql":
			continue // a deleted file
		}
		writeMigrationFile(t, directory, entry.Name(), string(body))
	}
	writeMigrationFile(t, directory, "0005_future.up.sql", "SELECT 5;")

	err = verifyShippedMigrationChecksums(directory, shippedMigrationChecksums)
	if err == nil {
		t.Fatal("verifyShippedMigrationChecksums() error = nil for drifted files")
	}
	for _, want := range []string{
		"0001_initial.up.sql changed",
		"0004_storage_hardening.up.sql changed",
		"CRLF",
		"0003_scan_runs.down.sql is missing",
		"0005_future.up.sql is not in the frozen list",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}
