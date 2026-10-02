package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func renderHelp(t *testing.T, args ...string) string {
	t.Helper()
	command := newRootCmd()
	var out bytes.Buffer
	command.SetOut(&out)
	command.SetErr(&out)
	command.SetContext(context.Background())
	command.SetArgs(args)
	if err := command.Execute(); err != nil {
		t.Fatalf("Execute(%v) error = %v", args, err)
	}
	return out.String()
}

// TestRootHelpListsEverySubcommand keeps `layerleak --help` complete: every
// registered subcommand, plus cobra's completion and help, is listed with a
// one-line description.
func TestRootHelpListsEverySubcommand(t *testing.T) {
	help := renderHelp(t, "--help")
	_, commands, ok := strings.Cut(help, "Available Commands:\n")
	if !ok {
		t.Fatalf("root help has no command list:\n%s", help)
	}
	commands, _, _ = strings.Cut(commands, "\n\n")
	listed := make(map[string]string)
	for _, line := range strings.Split(commands, "\n") {
		name, description, _ := strings.Cut(strings.TrimSpace(line), " ")
		listed[name] = strings.TrimSpace(description)
	}
	want := []string{"baseline", "completion", "detectors", "help", "scan", "version"}
	for _, sub := range newRootCmd().Commands() {
		if !sub.Hidden && !slices.Contains(want, sub.Name()) {
			want = append(want, sub.Name())
		}
	}
	for _, name := range want {
		description, ok := listed[name]
		if !ok || description == "" || strings.Contains(description, "\n") {
			t.Errorf("root help does not list %q with a one-line description:\n%s", name, commands)
		}
	}
	if !strings.Contains(help, "layerleak scan --help") {
		t.Errorf("root help does not point at scan --help:\n%s", help)
	}
}

// TestScanHelpDocumentsExamplesExitCodesAndEnvironment pins the parts of
// `layerleak scan --help` automation relies on: three examples (one local
// input, one --baseline run), the 0/1/2/3 exit codes with --fail-on, and the
// environment variables that affect a scan.
func TestScanHelpDocumentsExamplesExitCodesAndEnvironment(t *testing.T) {
	help := renderHelp(t, "scan", "--help")

	_, examples, ok := strings.Cut(help, "Examples:\n")
	if !ok {
		t.Fatalf("scan help has no Examples section:\n%s", help)
	}
	examples, _, _ = strings.Cut(examples, "\n\nFlags:")
	var invocations []string
	for _, line := range strings.Split(examples, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "layerleak scan ") {
			invocations = append(invocations, line)
		}
	}
	if len(invocations) != 3 {
		t.Fatalf("scan help has %d example invocations, want 3:\n%s", len(invocations), examples)
	}
	hasLocal := slices.ContainsFunc(invocations, func(line string) bool {
		return strings.Contains(line, " oci:") || strings.Contains(line, " oci-archive:") || strings.Contains(line, " docker-archive:")
	})
	hasBaseline := slices.ContainsFunc(invocations, func(line string) bool { return strings.Contains(line, "--baseline ") })
	if !hasLocal || !hasBaseline {
		t.Fatalf("scan examples need a local input and a --baseline run: %q", invocations)
	}

	_, exitCodes, ok := strings.Cut(help, "Exit codes:\n")
	if !ok {
		t.Fatalf("scan help has no exit code table:\n%s", help)
	}
	exitCodes, _, _ = strings.Cut(exitCodes, "\n\n")
	for _, code := range []string{"  0  ", "  1  ", "  2  ", "  3  ", "--fail-on", "--allow-partial"} {
		if !strings.Contains(exitCodes, code) {
			t.Errorf("exit code table is missing %q:\n%s", code, exitCodes)
		}
	}
	if exitCodeFailure != 1 || exitCodeFindings != 2 || exitCodeIncomplete != 3 {
		t.Fatal("exit code constants changed; update scanLongHelp")
	}

	// Every variable config.Load reads for a scan (all but the API server's)
	// is named, and every LAYERLEAK_ name in the help is a real variable.
	source, err := os.ReadFile(filepath.Join("..", "config", "config.go"))
	if err != nil {
		t.Fatal(err)
	}
	known := make(map[string]bool)
	for _, match := range regexp.MustCompile(`"(LAYERLEAK_[A-Z0-9_]+)"`).FindAllStringSubmatch(string(source), -1) {
		known[match[1]] = true
	}
	if len(known) < 40 {
		t.Fatalf("found only %d variables in internal/config/config.go", len(known))
	}
	_, environment, ok := strings.Cut(help, "Environment variables")
	if !ok {
		t.Fatalf("scan help has no environment section:\n%s", help)
	}
	environment, _, _ = strings.Cut(environment, "\n\n")
	named := make(map[string]bool)
	for _, field := range strings.Fields(environment) {
		named[field] = true
	}
	for name := range known {
		if strings.HasPrefix(name, "LAYERLEAK_API_") {
			continue
		}
		if !named[name] {
			t.Errorf("scan help does not name %s", name)
		}
	}
	for name := range named {
		if strings.HasPrefix(name, "LAYERLEAK_") && !known[name] {
			t.Errorf("scan help names %s, which internal/config does not read", name)
		}
	}
	for _, name := range []string{"HTTPS_PROXY", "NO_PROXY", "TERM", "CI"} {
		if !named[name] {
			t.Errorf("scan help does not name %s", name)
		}
	}
}

// TestUsageErrorsPointAtHelp keeps a pointer to --help on the errors cobra
// reports before a scan starts, since usage is silenced.
func TestUsageErrorsPointAtHelp(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"scan", "--bogus", "alpine:3.20"}, "unknown flag: --bogus; run 'layerleak scan --help' for usage"},
		{[]string{"scan"}, "accepts 1 arg(s), received 0; run 'layerleak scan --help' for usage"},
		{[]string{"detectors", "list", "--bogus"}, "run 'layerleak detectors list --help' for usage"},
	}
	for _, item := range cases {
		command := newRootCmd()
		var out bytes.Buffer
		command.SetOut(&out)
		command.SetErr(&out)
		command.SetContext(context.Background())
		command.SetArgs(item.args)
		err := command.Execute()
		if err == nil {
			t.Fatalf("Execute(%v) error = nil", item.args)
		}
		if !strings.Contains(err.Error(), item.want) {
			t.Errorf("Execute(%v) error = %q, want it to contain %q", item.args, err.Error(), item.want)
		}
		if exitCodeOf(t, err) != exitCodeFailure {
			t.Errorf("Execute(%v) exit = %d, want %d", item.args, exitCodeOf(t, err), exitCodeFailure)
		}
	}
}
