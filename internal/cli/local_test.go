package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brumbelow/layerleak/v3/internal/manifest"
	"github.com/brumbelow/layerleak/v3/internal/scanservice"
)

// localSyntheticToken has a GitHub token shape and is obviously not one.
const localSyntheticToken = "ghp_123456789012345678901234567890123456"

type localTarFile struct {
	name string
	body []byte
}

func localTar(t *testing.T, files []localTarFile) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, file := range files {
		if err := writer.WriteHeader(&tar.Header{Name: file.name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(file.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(file.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func localGzip(t *testing.T, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func localWrite(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeLocalLayout writes an OCI image layout with one linux/amd64 image
// tagged tag whose single layer holds the synthetic token, and returns the
// manifest digest.
func writeLocalLayout(t *testing.T, dir, tag string) string {
	t.Helper()
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["A=b"]}}`)
	layer := localGzip(t, localTar(t, []localTarFile{{name: "app/.env", body: []byte("TOKEN=" + localSyntheticToken + "\n")}}))
	configDescriptor := commandDescriptor(t, manifest.MediaTypeOCIImageConfig, config)
	layerDescriptor := commandDescriptor(t, manifest.MediaTypeOCIImageLayerGzip, layer)
	body, err := json.Marshal(manifest.ImageManifest{SchemaVersion: 2, MediaType: manifest.MediaTypeOCIImageManifest, Config: configDescriptor, Layers: []manifest.Descriptor{layerDescriptor}})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := commandDescriptor(t, manifest.MediaTypeOCIImageManifest, body)
	descriptor.Platform = manifest.Platform{OS: "linux", Architecture: "amd64"}
	descriptor.Annotations = map[string]string{"org.opencontainers.image.ref.name": tag}
	for digest, blob := range map[string][]byte{configDescriptor.Digest: config, layerDescriptor.Digest: layer, descriptor.Digest: body} {
		algorithm, encoded, _ := strings.Cut(digest, ":")
		localWrite(t, filepath.Join(dir, "blobs", algorithm, encoded), blob)
	}
	localWrite(t, filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`))
	localWrite(t, filepath.Join(dir, "index.json"), commandIndexBody(t, descriptor))
	return descriptor.Digest
}

// writeLocalDockerArchive writes a docker save archive with two images: one
// tagged app:1.0 and app:latest holding the synthetic token, one tagged
// app:2.0 that is clean.
func writeLocalDockerArchive(t *testing.T, path string) {
	t.Helper()
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["A=b"]}}`)
	cleanConfig := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["C=d"]}}`)
	layer := localTar(t, []localTarFile{{name: "app/.env", body: []byte("TOKEN=" + localSyntheticToken + "\n")}})
	_, configHex, _ := strings.Cut(commandDescriptor(t, "", config).Digest, ":")
	_, cleanHex, _ := strings.Cut(commandDescriptor(t, "", cleanConfig).Digest, ":")
	_, layerHex, _ := strings.Cut(commandDescriptor(t, "", layer).Digest, ":")
	manifestJSON := `[{"Config":"` + configHex + `.json","RepoTags":["app:1.0","app:latest"],"Layers":["` + layerHex + `/layer.tar"]},` +
		`{"Config":"` + cleanHex + `.json","RepoTags":["app:2.0"],"Layers":[]}]`
	localWrite(t, path, localTar(t, []localTarFile{
		{name: configHex + ".json", body: config},
		{name: cleanHex + ".json", body: cleanConfig},
		{name: layerHex + "/layer.tar", body: layer},
		{name: "manifest.json", body: []byte(manifestJSON)},
	}))
}

func runScan(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	command := newRootCmd()
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetIn(strings.NewReader(stdin))
	command.SetContext(context.Background())
	command.SetArgs(append([]string{"scan"}, args...))
	err := command.Execute()
	return stdout.String(), stderr.String(), err
}

// exitCodeOf mirrors Run: nil is 0, a coded error its code and any other
// error exitCodeFailure.
func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return exitCodeFailure
}

func TestScanCommandScansAnOCILayoutDirectory(t *testing.T) {
	dir := t.TempDir()
	digest := writeLocalLayout(t, dir, "1.2")
	findingsDir := t.TempDir()
	t.Setenv("LAYERLEAK_FINDINGS_DIR", findingsDir)

	raw := "oci:" + dir + ":1.2"
	stdout, stderr, err := runScan(t, "", raw, "--format", "json", "--no-db")
	if code := exitCodeOf(t, err); code != exitCodeFindings {
		t.Fatalf("exit = %d (%v) stderr=%s", code, err, stderr)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not JSON: %v: %s", err, stdout)
	}
	if result["requested_reference"] != raw || result["repository"] != "oci:"+dir || result["resolved_reference"] != "oci:"+dir+"@"+digest || result["requested_digest"] != digest {
		t.Fatalf("result identity = %v %v %v %v", result["requested_reference"], result["repository"], result["resolved_reference"], result["requested_digest"])
	}
	if result["status"] != "completed" || result["total_findings"] != float64(1) || result["mode"] != "reference" {
		t.Fatalf("status=%v findings=%v mode=%v", result["status"], result["total_findings"], result["mode"])
	}
	if strings.Contains(stdout, localSyntheticToken) {
		t.Fatalf("stdout leaked the raw value: %s", stdout)
	}
	records, err := filepath.Glob(filepath.Join(findingsDir, "*.json"))
	if err != nil || len(records) != 1 {
		t.Fatalf("records = %v, %v", records, err)
	}
	record, err := os.ReadFile(records[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(record), `"repository": "oci:`+dir+`"`) || strings.Contains(string(record), localSyntheticToken) {
		t.Fatalf("record = %s", record)
	}

	// The summary renders the same local identity.
	summary, _, err := runScan(t, "", raw, "--no-db", "--no-artifacts")
	if exitCodeOf(t, err) != exitCodeFindings || !strings.Contains(summary, "oci:"+dir+"\n") || !strings.Contains(summary, "oci:"+dir+"@"+digest) {
		t.Fatalf("summary = %s (%v)", summary, err)
	}
}

func TestScanCommandScansADockerArchiveAndSweepsItsTags(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "app.tar")
	writeLocalDockerArchive(t, archive)
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	stdout, _, err := runScan(t, "", "docker-archive:"+archive+":app:2.0", "--format", "json", "--no-db", "--no-artifacts")
	if code := exitCodeOf(t, err); code != 0 {
		t.Fatalf("clean image exit = %d (%v): %s", code, err, stdout)
	}
	if err != nil {
		t.Fatalf("clean image error = %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if result["repository"] != "docker-archive:"+archive || result["total_findings"] != float64(0) {
		t.Fatalf("result = %v", result)
	}

	stdout, stderr, err := runScan(t, "", "docker-archive:"+archive, "--all-tags", "--format", "json", "--no-db", "--no-artifacts")
	if code := exitCodeOf(t, err); code != exitCodeFindings {
		t.Fatalf("sweep exit = %d (%v) stderr=%s", code, err, stderr)
	}
	if strings.Contains(stderr, "every public tag") {
		t.Fatalf("local sweep printed the registry warning: %s", stderr)
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if result["mode"] != "repository" || result["tags_enumerated"] != float64(3) || result["target_count"] != float64(2) || result["total_findings"] != float64(1) {
		t.Fatalf("sweep result = mode=%v tags=%v targets=%v findings=%v", result["mode"], result["tags_enumerated"], result["target_count"], result["total_findings"])
	}

	// A missing image name is a clear exit-1 error that lists what exists.
	_, _, err = runScan(t, "", "docker-archive:"+archive+":app:9.9", "--format", "json", "--no-db", "--no-artifacts")
	if exitCodeOf(t, err) != exitCodeFailure || !strings.Contains(err.Error(), `no image named "app:9.9"`) || !strings.Contains(err.Error(), "app:1.0") {
		t.Fatalf("missing name error = %v", err)
	}
	// An untagged selection of a multi-image archive is refused too.
	_, _, err = runScan(t, "", "docker-archive:"+archive, "--format", "json", "--no-db", "--no-artifacts")
	if exitCodeOf(t, err) != exitCodeFailure || !strings.Contains(err.Error(), "holds 2 images") {
		t.Fatalf("untagged selection error = %v", err)
	}
}

func TestScanCommandRefusesCredentialsForLocalSources(t *testing.T) {
	dir := t.TempDir()
	writeLocalLayout(t, dir, "1.0")
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	_, _, err := runScan(t, "synthetic-password\n", "oci:"+dir+":1.0", "--no-db", "--username", "robot", "--password-stdin")
	if exitCodeOf(t, err) != exitCodeFailure || !errors.Is(err, scanservice.ErrCredentialForLocalSource) || !strings.Contains(err.Error(), "--username/--password-stdin do not apply") {
		t.Fatalf("flag credential error = %v", err)
	}

	t.Setenv("LAYERLEAK_REGISTRY_USERNAME", "robot")
	t.Setenv("LAYERLEAK_REGISTRY_PASSWORD", "synthetic-password")
	_, _, err = runScan(t, "", "oci:"+dir+":1.0", "--no-db")
	if exitCodeOf(t, err) != exitCodeFailure || !errors.Is(err, scanservice.ErrCredentialForLocalSource) || !strings.Contains(err.Error(), "LAYERLEAK_REGISTRY_USERNAME") {
		t.Fatalf("configured credential error = %v", err)
	}
	if strings.Contains(err.Error(), "synthetic-password") {
		t.Fatalf("error leaked the password: %v", err)
	}
}

func TestScanCommandReportsMissingLocalSources(t *testing.T) {
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())
	missing := filepath.Join(t.TempDir(), "missing")
	_, _, err := runScan(t, "", "oci:"+missing, "--no-db", "--no-artifacts")
	if exitCodeOf(t, err) != exitCodeFailure || !strings.Contains(err.Error(), "open local image source") {
		t.Fatalf("missing layout error = %v", err)
	}
	_, _, err = runScan(t, "", "oci-archive:"+missing+".tar:1.0", "--no-db", "--no-artifacts")
	if exitCodeOf(t, err) != exitCodeFailure || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing archive error = %v", err)
	}
	_, _, err = runScan(t, "", "oci:", "--no-db", "--no-artifacts")
	if exitCodeOf(t, err) != exitCodeFailure || !strings.Contains(err.Error(), "requires a path") {
		t.Fatalf("empty path error = %v", err)
	}
}

// localTarDirectory packs a layout directory into a tar archive at path, as
// `buildx -o type=oci,dest=path` would.
func localTarDirectory(t *testing.T, dir, path string) {
	t.Helper()
	var files []localTarFile
	err := filepath.WalkDir(dir, func(name string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(dir, name)
		if err != nil {
			return err
		}
		files = append(files, localTarFile{name: filepath.ToSlash(relative), body: body})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	localWrite(t, path, localTar(t, files))
}

// TestScanCommandSelectsAndSweepsBuildxStyleRefNames covers the README flow
// `docker buildx build -o type=oci,dest=app.tar -t app:1.2` followed by
// `layerleak scan oci-archive:app.tar:app:1.2`: BuildKit records the ref.name
// docker.io/library/app:1.2, which carries colons and slashes.
func TestScanCommandSelectsAndSweepsBuildxStyleRefNames(t *testing.T) {
	const refName = "docker.io/library/app:1.2"
	dir := t.TempDir()
	digest := writeLocalLayout(t, dir, refName)
	archive := filepath.Join(t.TempDir(), "app.tar")
	localTarDirectory(t, dir, archive)
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	for _, raw := range []string{"oci-archive:" + archive + ":app:1.2", "oci-archive:" + archive + ":" + refName, "oci:" + dir + ":app:1.2"} {
		stdout, stderr, err := runScan(t, "", raw, "--format", "json", "--no-db", "--no-artifacts")
		if code := exitCodeOf(t, err); code != exitCodeFindings {
			t.Fatalf("%s exit = %d (%v) stderr=%s", raw, code, err, stderr)
		}
		var result map[string]any
		if err := json.Unmarshal([]byte(stdout), &result); err != nil {
			t.Fatalf("stdout is not JSON: %v: %s", err, stdout)
		}
		wantRepository := strings.TrimSuffix(strings.TrimSuffix(raw, ":app:1.2"), ":"+refName)
		if result["requested_reference"] != raw || result["repository"] != wantRepository || result["resolved_reference"] != wantRepository+"@"+digest || result["total_findings"] != float64(1) {
			t.Fatalf("%s result identity = %v %v %v findings=%v", raw, result["requested_reference"], result["repository"], result["resolved_reference"], result["total_findings"])
		}
	}

	// A tag the layout does not hold is a plain exit-1 error naming what it does hold.
	_, _, err := runScan(t, "", "oci:"+dir+":1.2", "--format", "json", "--no-db", "--no-artifacts")
	if exitCodeOf(t, err) != exitCodeFailure || !strings.Contains(err.Error(), `no image tagged "1.2"`) || !strings.Contains(err.Error(), refName) {
		t.Fatalf("missing tag error = %v", err)
	}

	for _, raw := range []string{"oci:" + dir, "oci-archive:" + archive} {
		stdout, stderr, err := runScan(t, "", raw, "--all-tags", "--format", "json", "--no-db", "--no-artifacts")
		if code := exitCodeOf(t, err); code != exitCodeFindings {
			t.Fatalf("%s sweep exit = %d (%v) stderr=%s stdout=%s", raw, code, err, stderr, stdout)
		}
		if strings.Contains(stderr, "every public tag") {
			t.Fatalf("local sweep printed the registry warning: %s", stderr)
		}
		var result struct {
			Mode           string `json:"mode"`
			Status         string `json:"status"`
			Repository     string `json:"repository"`
			TagsEnumerated int    `json:"tags_enumerated"`
			TagsResolved   int    `json:"tags_resolved"`
			TargetCount    int    `json:"target_count"`
			TotalFindings  int    `json:"total_findings"`
			TagResults     []struct {
				Tag             string `json:"tag"`
				RootDigest      string `json:"root_digest"`
				TargetReference string `json:"target_reference"`
				Status          string `json:"status"`
			} `json:"tag_results"`
			Targets []struct {
				Reference string `json:"reference"`
			} `json:"targets"`
		}
		if err := json.Unmarshal([]byte(stdout), &result); err != nil {
			t.Fatalf("stdout is not JSON: %v: %s", err, stdout)
		}
		if result.Mode != "repository" || result.Status != "completed" || result.Repository != raw || result.TagsEnumerated != 1 || result.TagsResolved != 1 || result.TargetCount != 1 || result.TotalFindings != 1 {
			t.Fatalf("%s sweep result = %+v", raw, result)
		}
		if len(result.TagResults) != 1 || result.TagResults[0].Tag != refName || result.TagResults[0].Status != "scanned" || result.TagResults[0].RootDigest != digest || result.TagResults[0].TargetReference != raw+"@"+digest {
			t.Fatalf("%s tag results = %+v", raw, result.TagResults)
		}
		if len(result.Targets) != 1 || result.Targets[0].Reference != raw+"@"+digest {
			t.Fatalf("%s targets = %+v", raw, result.Targets)
		}
	}
}
