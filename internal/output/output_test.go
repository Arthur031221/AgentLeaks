package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Arthur031221/agentleaks/internal/rules"
	"github.com/Arthur031221/agentleaks/internal/scan"
	"github.com/Arthur031221/agentleaks/internal/sources"
)

// Fixtures are assembled from fragments at run time so that no complete
// secret pattern ever appears in the repository.

func fakeGitHubPAT() string { return "ghp_" + strings.Repeat("ab", 18) }

func fakeAnthropicKey() string { return "sk-ant-" + "api03-" + strings.Repeat("Z7", 25) }

func finding(rule, provider, severity, tool, path string, line int, secret string, mod time.Time) scan.Finding {
	return scan.Finding{
		RuleID: rule, Provider: provider, Severity: severity, Tool: tool, ToolName: tool, Label: "fixture",
		Path: path, Line: line, Column: 1, Masked: rules.Mask(secret), Fingerprint: rules.Fingerprint(secret),
		ModTime: mod, Secret: secret,
	}
}

func fixtures() []scan.Finding {
	pat := fakeGitHubPAT()
	ant := fakeAnthropicKey()
	now := time.Now()
	return []scan.Finding{
		finding("github-pat", "GitHub", rules.SeverityHigh, "claude-code", "/h/.claude/history.jsonl", 4, pat, now),
		finding("github-pat", "GitHub", rules.SeverityHigh, "claude-code", "/h/.claude/history.jsonl", 9, pat, now),
		finding("generic-api-key", "Generic", rules.SeverityMedium, "codex", "/h/.codex/history.jsonl", 2, ant, now),
	}
}

func TestJSONReport(t *testing.T) {
	fs := fixtures()
	st := scan.Stats{Files: 12, Bytes: 4096, Duration: 1500 * time.Millisecond}
	var buf bytes.Buffer
	rep := Report{Version: "test", GeneratedAt: time.Now(), Summary: Summarize(fs, st), Findings: fs,
		Tools: []sources.Status{{Tool: "claude-code", Name: "Claude Code", Found: true, Files: 3}}}
	if err := JSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	raw := buf.String()
	for _, f := range fs {
		if strings.Contains(raw, f.Secret) {
			t.Fatal("JSON report contains a secret")
		}
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	s := back.Summary
	if s.Findings != 3 || s.Distinct != 2 || s.Files != 2 || s.Tools != 2 {
		t.Errorf("summary = %+v", s)
	}
	if s.ScannedFiles != 12 || s.ScannedBytes != 4096 || s.DurationMS != 1500 {
		t.Errorf("scan stats = %+v", s)
	}
	if len(back.Findings) != 3 || back.Findings[0].Masked != rules.Mask(fs[0].Secret) {
		t.Errorf("findings round trip = %+v", back.Findings)
	}
	if len(back.Tools) != 1 || !back.Tools[0].Found {
		t.Errorf("tools round trip = %+v", back.Tools)
	}
	var generic map[string]any
	if err := json.Unmarshal(buf.Bytes(), &generic); err != nil {
		t.Fatal(err)
	}
	if _, ok := generic["findings"].([]any)[0].(map[string]any)["secret"]; ok {
		t.Error("finding serialised a secret field")
	}

	buf.Reset()
	if err := JSON(&buf, Report{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) || !strings.Contains(buf.String(), `"tools": []`) {
		t.Errorf("empty report must use empty arrays, got %s", buf.String())
	}
}

func TestSummarizeVerified(t *testing.T) {
	fs := fixtures()
	fs[0].Status = "live"
	fs[1].Status = "live"
	fs[2].Status = "dead"
	s := Summarize(fs, scan.Stats{})
	if s.Live != 2 || s.Dead != 1 {
		t.Errorf("live/dead = %d/%d", s.Live, s.Dead)
	}
	line := SummaryLine(fs, scan.Stats{Files: 3}, nil)
	if !strings.Contains(line, "Verified: 2 live, 1 dead") {
		t.Errorf("summary line = %q", line)
	}
}

func TestSARIF(t *testing.T) {
	fs := fixtures()
	set := rules.MustLoad()
	var buf bytes.Buffer
	if err := SARIF(&buf, fs, set, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	raw := buf.String()
	for _, f := range fs {
		if strings.Contains(raw, f.Secret) {
			t.Fatal("SARIF contains a secret")
		}
	}
	var doc struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID       string            `json:"ruleId"`
				Level        string            `json:"level"`
				Fingerprints map[string]string `json:"partialFingerprints"`
				Locations    []struct {
					Physical struct {
						Artifact struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || doc.Schema == "" || len(doc.Runs) != 1 {
		t.Fatalf("header = %+v", doc)
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "agentleaks" || run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Results) != len(fs) {
		t.Fatalf("results = %d, want %d", len(run.Results), len(fs))
	}
	seen := map[string]int{}
	for _, r := range run.Tool.Driver.Rules {
		seen[r.ID]++
	}
	if seen["github-pat"] != 1 || seen["generic-api-key"] != 1 || len(seen) != 2 {
		t.Errorf("rules listed = %v", seen)
	}
	if run.Results[0].Level != "error" || run.Results[2].Level != "warning" {
		t.Errorf("levels = %s, %s", run.Results[0].Level, run.Results[2].Level)
	}
	if run.Results[0].Fingerprints["agentleaks/v1"] != fs[0].Fingerprint {
		t.Error("fingerprint missing")
	}
	loc := run.Results[0].Locations[0].Physical
	if loc.Artifact.URI != "file:///h/.claude/history.jsonl" || loc.Region.StartLine != 4 {
		t.Errorf("location = %+v", loc)
	}

	buf.Reset()
	if err := SARIF(&buf, nil, set, "x"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"results": []`) || !strings.Contains(buf.String(), `"rules": []`) {
		t.Errorf("empty SARIF must use empty arrays: %s", buf.String())
	}
}

func TestTableGroupedAndAll(t *testing.T) {
	fs := fixtures()
	var buf bytes.Buffer
	Table(&buf, fs, TableOptions{Home: "/h"})
	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("grouped table has %d lines, want header plus 2 rows:\n%s", len(lines), out)
	}
	head := lines[0]
	for _, col := range []string{"PROVIDER", "TOOL", "FILE", "WHERE", "PREVIEW", "AGE", "HITS"} {
		if !strings.Contains(head, col) {
			t.Errorf("header missing %s: %s", col, head)
		}
	}
	if !strings.Contains(lines[1], "~/.claude/history.jsonl") || !strings.HasSuffix(strings.TrimSpace(lines[1]), "2") {
		t.Errorf("grouped row should show 2 hits: %s", lines[1])
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("escape codes present with colour off")
	}
	for _, f := range fs {
		if strings.Contains(out, f.Secret) {
			t.Fatal("table contains a secret")
		}
	}
	if !strings.Contains(out, rules.Mask(fs[0].Secret)) {
		t.Error("masked preview missing")
	}

	buf.Reset()
	Table(&buf, fs, TableOptions{Home: "/h", All: true})
	lines = strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Errorf("all mode has %d lines, want header plus 3 rows", len(lines))
	}
	if strings.Contains(lines[0], "HITS") {
		t.Error("all mode must not show a HITS column")
	}

	buf.Reset()
	Table(&buf, nil, TableOptions{})
	if buf.Len() != 0 {
		t.Error("empty findings must print nothing")
	}

	buf.Reset()
	fs[0].Status = "live"
	Table(&buf, fs, TableOptions{Home: "/h", Verified: true, Color: true})
	if !strings.Contains(buf.String(), "STATUS") || !strings.Contains(buf.String(), "\x1b[31mlive") {
		t.Errorf("verified colour table:\n%s", buf.String())
	}
}

func TestGroupFindings(t *testing.T) {
	gs := GroupFindings(fixtures())
	if len(gs) != 2 || gs[0].Count != 2 || gs[1].Count != 1 {
		t.Errorf("groups = %+v", gs)
	}
}

func TestSummaryLineEmpty(t *testing.T) {
	statuses := []sources.Status{{Tool: "a", Found: true}, {Tool: "b", Found: false}}
	line := SummaryLine(nil, scan.Stats{Files: 5, Bytes: 2048, Duration: time.Second}, statuses)
	if !strings.HasPrefix(line, "No secrets found.") || !strings.Contains(line, "5 files") || !strings.Contains(line, "from 1 tools") {
		t.Errorf("summary line = %q", line)
	}
	line = SummaryLine(fixtures(), scan.Stats{Files: 5}, statuses)
	if !strings.HasPrefix(line, "3 secrets (2 distinct) in 2 files across 2 tools.") {
		t.Errorf("summary line = %q", line)
	}
}

func TestAge(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "now"},
		{5 * time.Minute, "5m"},
		{3 * time.Hour, "3h"},
		{5 * 24 * time.Hour, "5d"},
		{90 * 24 * time.Hour, "3mo"},
		{730 * 24 * time.Hour, "2y"},
	}
	for _, c := range cases {
		if got := Age(now, now.Add(-c.d)); got != c.want {
			t.Errorf("Age(%v) = %q, want %q", c.d, got, c.want)
		}
	}
	if got := Age(now, time.Time{}); got != "-" {
		t.Errorf("Age(zero) = %q", got)
	}
}

func TestBytes(t *testing.T) {
	cases := map[int64]string{512: "512 B", 2048: "2.0 KB", 5 << 20: "5.0 MB"}
	for n, want := range cases {
		if got := Bytes(n); got != want {
			t.Errorf("Bytes(%d) = %q, want %q", n, got, want)
		}
	}
}
