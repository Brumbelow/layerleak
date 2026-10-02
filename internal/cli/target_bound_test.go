package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanCommandAppliesTheTargetBoundToLocalSweeps sweeps a docker save
// archive holding two distinct images with --max-repository-targets 1: the
// local source's tags are bounded exactly like a registry's, the sweep fails
// with the repository target limit and every enumerated tag is reported.
func TestScanCommandAppliesTheTargetBoundToLocalSweeps(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "app.tar")
	writeLocalDockerArchive(t, archive)
	t.Setenv("LAYERLEAK_FINDINGS_DIR", t.TempDir())

	stdout, _, err := runScan(t, "", "docker-archive:"+archive, "--all-tags", "--max-repository-targets", "1", "--format", "json", "--no-db", "--no-artifacts")
	if err == nil || !strings.Contains(err.Error(), "max repository targets limit of 1") {
		t.Fatalf("sweep error = %v, want the repository target limit", err)
	}
	if exitCodeOf(t, err) != exitCodeFailure {
		t.Fatalf("sweep exit = %d, want %d", exitCodeOf(t, err), exitCodeFailure)
	}
	var result struct {
		Status         string `json:"status"`
		TagsEnumerated int    `json:"tags_enumerated"`
		TargetCount    int    `json:"target_count"`
		TagResults     []struct {
			Tag    string `json:"tag"`
			Status string `json:"status"`
		} `json:"tag_results"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode result: %v\n%s", err, stdout)
	}
	if result.Status != "failed" || result.TagsEnumerated != 3 || result.TargetCount != 2 || len(result.TagResults) != 3 {
		t.Fatalf("result = %+v", result)
	}
}
