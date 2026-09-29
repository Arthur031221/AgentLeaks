package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arthur031221/agentleaks/internal/fix"
	"github.com/Arthur031221/agentleaks/internal/output"
	"github.com/Arthur031221/agentleaks/internal/rules"
)

// Fixtures are assembled from fragments at run time so that no complete
// secret pattern ever appears in the repository.

func fakeGitHubPAT() string { return "ghp_" + strings.Repeat("ab", 18) }

// home builds a synthetic home directory with one Claude Code history file
// that contains a fake token.
func home(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	pat := fakeGitHubPAT()
	path := filepath.Join(dir, ".claude", "history.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := `{"display":"hello","project":"/p"}` + "\n" + `{"display":"use ` + pat + ` for auth","project":"/p"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Main(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestScanTable(t *testing.T) {
	dir, _ := home(t)
	pat := fakeGitHubPAT()
	code, out, _ := run(t, "", "scan", "--home", dir, "--no-color", "--quiet")
	if code != ExitFindings {
		t.Fatalf("exit %d, want %d\n%s", code, ExitFindings, out)
	}
	if !strings.Contains(out, "PROVIDER") || !strings.Contains(out, "GitHub") {
		t.Errorf("table missing header or provider:\n%s", out)
	}
	if !strings.Contains(out, pat[:6]+"...") {
		t.Errorf("masked preview missing:\n%s", out)
	}
	if strings.Contains(out, pat) {
		t.Error("output leaks the secret")
	}
	if !strings.Contains(out, "1 secrets (1 distinct) in 1 files across 1 tools") {
		t.Errorf("summary missing:\n%s", out)
	}
	if !strings.Contains(out, "agentleaks fix") {
		t.Errorf("next step hint missing:\n%s", out)
	}
}

func TestScanJSON(t *testing.T) {
	dir, _ := home(t)
	code, out, _ := run(t, "", "scan", "--home", dir, "--json", "--quiet")
	if code != ExitFindings {
		t.Fatalf("exit %d", code)
	}
	var rep output.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if rep.Summary.Findings != 1 || rep.Summary.Distinct != 1 {
		t.Errorf("summary = %+v", rep.Summary)
	}
	found := false
	for _, s := range rep.Tools {
		if s.Tool == "claude-code" && s.Found {
			found = true
		}
	}
	if !found {
		t.Errorf("claude-code not reported as found: %+v", rep.Tools)
	}
	if strings.Contains(out, fakeGitHubPAT()) {
		t.Error("JSON leaks the secret")
	}
}

func TestScanSARIF(t *testing.T) {
	dir, _ := home(t)
	code, out, _ := run(t, "", "scan", "--home", dir, "--sarif", "--quiet")
	if code != ExitFindings {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("bad SARIF: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Errorf("SARIF = %+v", doc)
	}
}

func TestScanEmptyHome(t *testing.T) {
	dir := t.TempDir()
	code, out, _ := run(t, "", "scan", "--home", dir, "--quiet")
	if code != ExitClean {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "No supported AI tool data found") {
		t.Errorf("output:\n%s", out)
	}
}

func TestScanExplicitPath(t *testing.T) {
	_, path := home(t)
	code, out, _ := run(t, "", "scan", "--quiet", "--no-color", path)
	if code != ExitFindings || !strings.Contains(out, "GitHub") {
		t.Errorf("exit %d\n%s", code, out)
	}
	code, _, errOut := run(t, "", "scan", "--quiet", filepath.Join(t.TempDir(), "missing.jsonl"))
	if code != ExitError || !strings.Contains(errOut, "agentleaks:") {
		t.Errorf("missing path: exit %d stderr %q", code, errOut)
	}
}

func TestScanFilters(t *testing.T) {
	dir, _ := home(t)
	code, out, _ := run(t, "", "scan", "--home", dir, "--quiet", "--rule", "aws-access-key-id")
	if code != ExitClean || !strings.Contains(out, "No secrets found") {
		t.Errorf("rule filter: exit %d\n%s", code, out)
	}
	code, _, _ = run(t, "", "scan", "--home", dir, "--quiet", "--min-severity", "high")
	if code != ExitFindings {
		t.Errorf("min-severity high dropped a high finding: exit %d", code)
	}
	code, _, _ = run(t, "", "scan", "--home", dir, "--quiet", "--exit-zero")
	if code != ExitClean {
		t.Errorf("--exit-zero: exit %d", code)
	}
	code, _, errOut := run(t, "", "scan", "--home", dir, "--quiet", "--tool", "nope")
	if code != ExitError || !strings.Contains(errOut, "unknown tool") {
		t.Errorf("unknown tool: exit %d stderr %q", code, errOut)
	}
	code, _, _ = run(t, "", "scan", "--home", dir, "--quiet", "--tool", "codex")
	if code != ExitClean {
		t.Errorf("tool filter to codex should find nothing: exit %d", code)
	}
}

func TestFixDryRunAndApply(t *testing.T) {
	dir, path := home(t)
	pat := fakeGitHubPAT()
	before, _ := os.ReadFile(path)
	code, out, _ := run(t, "", "fix", "--home", dir, "--quiet")
	if code != ExitClean || !strings.Contains(out, "Dry run") || !strings.Contains(out, "would redact") {
		t.Fatalf("dry run: exit %d\n%s", code, out)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("dry run changed the file")
	}
	backup := filepath.Join(dir, "bk")
	code, out, _ = run(t, "", "fix", "--home", dir, "--quiet", "--yes", "--backup-dir", backup)
	if code != ExitClean || !strings.Contains(out, "Redacted 1 secrets in 1 files") {
		t.Fatalf("apply: exit %d\n%s", code, out)
	}
	after, _ = os.ReadFile(path)
	if bytes.Contains(after, []byte(pat)) || !bytes.Contains(after, []byte("[REDACTED:github-pat]")) {
		t.Errorf("file not redacted: %s", after)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(after), []byte("\n")) {
		if !json.Valid(line) {
			t.Errorf("invalid JSONL after fix: %s", line)
		}
	}
	copyPath := filepath.Join(backup, strings.TrimPrefix(path, string(filepath.Separator)))
	if b, err := os.ReadFile(copyPath); err != nil || !bytes.Contains(b, []byte(pat)) {
		t.Errorf("backup missing or wrong at %s: %v", copyPath, err)
	}
	if !strings.Contains(out, backup) {
		t.Errorf("backup location not printed:\n%s", out)
	}
	code, out, _ = run(t, "", "fix", "--home", dir, "--quiet")
	if code != ExitClean || !strings.Contains(out, "Nothing to fix") {
		t.Errorf("second dry run: exit %d\n%s", code, out)
	}
}

func TestFixJSON(t *testing.T) {
	dir, _ := home(t)
	code, out, _ := run(t, "", "fix", "--home", dir, "--quiet", "--yes", "--json", "--no-backup")
	if code != ExitClean {
		t.Fatalf("exit %d\n%s", code, out)
	}
	var results []fix.Result
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if len(results) != 1 || results[0].Redacted != 1 || results[0].DryRun {
		t.Errorf("results = %+v", results)
	}
	code, out, _ = run(t, "", "fix", "--home", dir, "--quiet", "--json")
	if code != ExitClean || strings.TrimSpace(out) != "[]" {
		t.Errorf("nothing to fix should print []: %q", out)
	}
}

func TestReportToFile(t *testing.T) {
	dir, _ := home(t)
	outPath := filepath.Join(dir, "report.json")
	code, _, errOut := run(t, "", "report", "--home", dir, "-o", outPath)
	if code != ExitFindings {
		t.Fatalf("exit %d", code)
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var rep output.Report
	if err := json.Unmarshal(b, &rep); err != nil || rep.Summary.Findings != 1 {
		t.Errorf("report file: %v %+v", err, rep.Summary)
	}
	if !strings.Contains(errOut, "Wrote") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestGuardLifecycle(t *testing.T) {
	dir, _ := home(t)
	code, out, _ := run(t, "", "guard", "--home", dir, "--dry-run")
	if code != ExitClean || !strings.Contains(out, "would-install") {
		t.Fatalf("dry run: exit %d\n%s", code, out)
	}
	settings := filepath.Join(dir, ".claude", "settings.json")
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Fatal("dry run wrote settings")
	}

	code, out, _ = run(t, "", "guard", "--home", dir, "--coverage")
	if code != ExitClean {
		t.Fatalf("coverage: exit %d", code)
	}
	for _, tool := range []string{"claude-code", "codex", "cursor", "gemini", "copilot"} {
		if !strings.Contains(out, tool) {
			t.Errorf("coverage missing %s:\n%s", tool, out)
		}
	}

	code, out, _ = run(t, "", "guard", "--home", dir, "--binary", "/usr/local/bin/agentleaks")
	if code != ExitClean || !strings.Contains(out, "installed") {
		t.Fatalf("install: exit %d\n%s", code, out)
	}
	b, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "agentleaks hook claude-code PreToolUse") {
		t.Errorf("settings missing hook:\n%s", b)
	}
	if !json.Valid(b) {
		t.Error("settings not valid JSON")
	}

	code, out, _ = run(t, "", "guard", "--home", dir, "--json")
	if code != ExitClean || !strings.Contains(out, "already-installed") {
		t.Errorf("second install: exit %d\n%s", code, out)
	}

	code, out, _ = run(t, "", "guard", "--home", dir, "--uninstall")
	if code != ExitClean || !strings.Contains(out, "removed") {
		t.Fatalf("uninstall: exit %d\n%s", code, out)
	}
	b, _ = os.ReadFile(settings)
	if strings.Contains(string(b), "agentleaks hook") {
		t.Errorf("hook still present after uninstall:\n%s", b)
	}
}

func TestHook(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENTLEAKS_HOME", dir)
	payload := `{"tool_name":"Read","tool_input":{"file_path":"` + filepath.Join(dir, ".env") + `"}}`
	code, _, errOut := run(t, payload, "hook", "claude-code", "PreToolUse")
	if code != 2 || !strings.Contains(errOut, "blocked") {
		t.Errorf("deny: exit %d stderr %q", code, errOut)
	}
	code, out, errOut := run(t, "this is not json", "hook", "claude-code", "PreToolUse")
	if code != 0 || out != "" || errOut != "" {
		t.Errorf("garbage stdin must fail open: exit %d out %q err %q", code, out, errOut)
	}
	code, _, _ = run(t, "", "hook", "claude-code")
	if code != ExitError {
		t.Errorf("missing event should be a usage error, exit %d", code)
	}
}

func TestRules(t *testing.T) {
	set := rules.MustLoad()
	code, out, _ := run(t, "", "rules")
	if code != ExitClean {
		t.Fatalf("exit %d", code)
	}
	want := fmt.Sprintf("%d rules.", len(set.Rules))
	if !strings.HasSuffix(strings.TrimSpace(out), want) {
		t.Errorf("rules output should end with %q:\n%s", want, out[len(out)-40:])
	}
	code, out, _ = run(t, "", "rules", "--json")
	if code != ExitClean {
		t.Fatalf("exit %d", code)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != len(set.Rules) {
		t.Errorf("rules --json: %v, %d rows", err, len(rows))
	}
	code, out, _ = run(t, "", "rules", "--tools")
	if code != ExitClean || !strings.Contains(out, "Claude Code") || !strings.Contains(out, "~/.claude/projects/**/*.jsonl") {
		t.Errorf("rules --tools:\n%s", out)
	}
	code, out, _ = run(t, "", "rules", "--tools", "--json")
	if code != ExitClean || !strings.Contains(out, `"id": "claude-code"`) {
		t.Errorf("rules --tools --json:\n%s", out)
	}
}

func TestMisc(t *testing.T) {
	code, out, _ := run(t, "", "version")
	if code != ExitClean || !strings.Contains(out, "agentleaks") {
		t.Errorf("version: %d %q", code, out)
	}
	code, out, _ = run(t, "", "help")
	if code != ExitClean || !strings.Contains(out, "Usage:") {
		t.Errorf("help: %d %q", code, out)
	}
	code, _, errOut := run(t, "", "bogus")
	if code != ExitError || !strings.Contains(errOut, "unknown command") {
		t.Errorf("bogus: %d %q", code, errOut)
	}
	code, _, _ = run(t, "", "scan", "--help")
	if code != ExitClean {
		t.Errorf("scan --help: %d", code)
	}
	for _, cmd := range []string{"fix", "guard", "rules", "report", "verify"} {
		if code, _, _ = run(t, "", cmd, "--help"); code != ExitClean {
			t.Errorf("%s --help: %d", cmd, code)
		}
	}
}

func TestNoArgsScans(t *testing.T) {
	dir, _ := home(t)
	t.Setenv("AGENTLEAKS_HOME", dir)
	code, out, _ := run(t, "")
	if code != ExitFindings || !strings.Contains(out, "GitHub") {
		t.Errorf("no args: exit %d\n%s", code, out)
	}
	code, out, _ = run(t, "", "--json", "--quiet")
	if code != ExitFindings || !strings.Contains(out, `"findings"`) {
		t.Errorf("bare flags: exit %d\n%s", code, out)
	}
}

func TestVerifyRefusesWithoutConsent(t *testing.T) {
	dir, _ := home(t)
	code, _, errOut := run(t, "", "scan", "--home", dir, "--quiet", "--verify")
	if code != ExitError || !strings.Contains(errOut, "Pass --yes") {
		t.Errorf("verify without consent: exit %d stderr %q", code, errOut)
	}
	if !strings.Contains(errOut, "github") {
		t.Errorf("consent notice should name the provider: %q", errOut)
	}
	code, _, errOut = run(t, "", "verify", "--home", dir, "--quiet")
	if code != ExitError || !strings.Contains(errOut, "Pass --yes") {
		t.Errorf("verify command without consent: exit %d stderr %q", code, errOut)
	}
	// Nothing verifiable: the notice is skipped and the scan proceeds.
	empty := t.TempDir()
	code, _, errOut = run(t, "", "scan", "--home", empty, "--verify")
	if code != ExitClean || !strings.Contains(errOut, "Nothing to verify") {
		t.Errorf("empty verify: exit %d stderr %q", code, errOut)
	}
}
