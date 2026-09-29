package guard

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSecret builds a value that matches the anthropic-api-key rule. It is
// assembled from fragments so no secret-shaped literal exists in the source.
func fakeSecret() string {
	return "sk-ant-" + "api03-" + strings.Repeat("x9", 25)
}

func run(t *testing.T, tool, event, payload string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(tool, event, strings.NewReader(payload), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func parseJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("output is not JSON: %q: %v", s, err)
	}
	return m
}

func TestRunClaudeCodePreToolUse(t *testing.T) {
	t.Setenv("AGENTLEAKS_HOME", t.TempDir())
	code, out, errOut := run(t, ToolClaudeCode, "PreToolUse", `{"tool_name":"Read","tool_input":{"file_path":"/srv/app/.env"}}`)
	if code != 2 || out != "" || !strings.Contains(errOut, "agentleaks") {
		t.Errorf("deny: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run(t, ToolClaudeCode, "PreToolUse", `{"tool_name":"Bash","tool_input":{"command":"cat ~/.aws/credentials"}}`)
	if code != 2 || out != "" || errOut == "" {
		t.Errorf("deny bash: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run(t, ToolClaudeCode, "PreToolUse", `{"tool_name":"Grep","tool_input":{"pattern":"KEY","paths":["src","/home/x/.ssh"]}}`)
	if code != 2 {
		t.Errorf("deny grep paths: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run(t, ToolClaudeCode, "PreToolUse", `{"tool_name":"Read","tool_input":{"file_path":"/srv/app/main.go"}}`)
	if code != 0 || out != "" || errOut != "" {
		t.Errorf("allow: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run(t, ToolClaudeCode, "PreToolUse", `{"tool_name":"Bash","tool_input":{"command":"go test ./..."}}`)
	if code != 0 || out != "" || errOut != "" {
		t.Errorf("allow bash: code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestRunClaudeCodePostToolUse(t *testing.T) {
	secret := fakeSecret()
	payload, _ := json.Marshal(map[string]any{
		"tool_name":   "Read",
		"tool_input":  map[string]any{"file_path": "/srv/app/config.txt"},
		"tool_output": "ANTHROPIC_API_KEY=" + secret + "\nOTHER=1\n",
	})
	code, out, _ := run(t, ToolClaudeCode, "PostToolUse", string(payload))
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	m := parseJSON(t, out)
	hso, _ := m["hookSpecificOutput"].(map[string]any)
	if hso["hookEventName"] != "PostToolUse" {
		t.Errorf("hookEventName = %v", hso["hookEventName"])
	}
	updated, _ := hso["updatedToolOutput"].(string)
	if strings.Contains(updated, secret) {
		t.Error("secret survived redaction")
	}
	if !strings.Contains(updated, "[REDACTED:anthropic-api-key]") || !strings.Contains(updated, "OTHER=1") {
		t.Errorf("unexpected updatedToolOutput: %q", updated)
	}

	// Object form under tool_response.
	payload, _ = json.Marshal(map[string]any{
		"tool_name":     "Bash",
		"tool_input":    map[string]any{"command": "printenv X"},
		"tool_response": map[string]any{"stdout": "key " + secret, "stderr": "", "n": 1},
	})
	code, out, _ = run(t, ToolClaudeCode, "PostToolUse", string(payload))
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	m = parseJSON(t, out)
	hso, _ = m["hookSpecificOutput"].(map[string]any)
	obj, _ := hso["updatedToolOutput"].(map[string]any)
	if s, _ := obj["stdout"].(string); strings.Contains(s, secret) || !strings.Contains(s, "[REDACTED:") {
		t.Errorf("object redaction failed: %v", obj)
	}
	if obj["n"] != float64(1) {
		t.Errorf("non-string fields must survive: %v", obj)
	}

	// Clean output prints nothing.
	code, out, _ = run(t, ToolClaudeCode, "PostToolUse", `{"tool_name":"Read","tool_output":"hello world"}`)
	if code != 0 || out != "" {
		t.Errorf("clean: code=%d out=%q", code, out)
	}
}

func TestRunCodex(t *testing.T) {
	t.Setenv("AGENTLEAKS_HOME", t.TempDir())
	code, out, errOut := run(t, ToolCodex, "PreToolUse", `{"tool_name":"Bash","tool_input":{"command":"cat .env"}}`)
	if code != 2 || out != "" || errOut == "" {
		t.Errorf("deny: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run(t, ToolCodex, "PreToolUse", `{"tool_name":"Bash","tool_input":{"command":"ls"}}`)
	if code != 0 || out != "" || errOut != "" {
		t.Errorf("allow: code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestRunCursor(t *testing.T) {
	t.Setenv("AGENTLEAKS_HOME", t.TempDir())
	code, out, _ := run(t, ToolCursor, "beforeShellExecution", `{"command":"cat .env","cwd":"/srv"}`)
	m := parseJSON(t, out)
	if code != 0 || m["permission"] != "deny" || m["user_message"] == "" || m["agent_message"] == "" {
		t.Errorf("deny shell: code=%d out=%q", code, out)
	}
	code, out, _ = run(t, ToolCursor, "beforeReadFile", `{"file_path":"/srv/.env","content":"X=1","attachments":[]}`)
	m = parseJSON(t, out)
	if code != 0 || m["permission"] != "deny" {
		t.Errorf("deny read: code=%d out=%q", code, out)
	}
	code, out, _ = run(t, ToolCursor, "beforeReadFile", `{"file_path":"/srv/main.go","content":"","attachments":[{"type":"file","file_path":"/srv/.ssh/id_rsa"}]}`)
	m = parseJSON(t, out)
	if code != 0 || m["permission"] != "deny" {
		t.Errorf("deny attachment: code=%d out=%q", code, out)
	}
	code, out, _ = run(t, ToolCursor, "beforeReadFile", `{"file_path":"/srv/main.go","content":"package main","attachments":[]}`)
	m = parseJSON(t, out)
	if code != 0 || m["permission"] != "allow" {
		t.Errorf("allow: code=%d out=%q", code, out)
	}
}

func TestRunGemini(t *testing.T) {
	t.Setenv("AGENTLEAKS_HOME", t.TempDir())
	code, out, _ := run(t, ToolGemini, "BeforeTool", `{"tool_name":"read_file","tool_input":{"absolute_path":"/srv/.env"}}`)
	m := parseJSON(t, out)
	if code != 0 || m["decision"] != "deny" || m["reason"] == "" {
		t.Errorf("deny read: code=%d out=%q", code, out)
	}
	code, out, _ = run(t, ToolGemini, "BeforeTool", `{"tool_name":"run_shell_command","tool_input":{"command":"cat ~/.netrc"}}`)
	m = parseJSON(t, out)
	if code != 0 || m["decision"] != "deny" {
		t.Errorf("deny shell: code=%d out=%q", code, out)
	}
	code, out, _ = run(t, ToolGemini, "BeforeTool", `{"tool_name":"read_many_files","tool_input":{"paths":["src/a.go","secrets.yaml"]}}`)
	m = parseJSON(t, out)
	if code != 0 || m["decision"] != "deny" {
		t.Errorf("deny many: code=%d out=%q", code, out)
	}
	code, out, _ = run(t, ToolGemini, "BeforeTool", `{"tool_name":"read_file","tool_input":{"absolute_path":"/srv/main.go"}}`)
	if code != 0 || out != "" {
		t.Errorf("allow: code=%d out=%q", code, out)
	}
}

func TestRunCopilot(t *testing.T) {
	t.Setenv("AGENTLEAKS_HOME", t.TempDir())
	code, out, _ := run(t, ToolCopilot, "preToolUse", `{"sessionId":"s","toolName":"view","toolArgs":{"path":"/srv/.env"}}`)
	m := parseJSON(t, out)
	if code != 0 || m["permissionDecision"] != "deny" || m["permissionDecisionReason"] == "" {
		t.Errorf("deny read: code=%d out=%q", code, out)
	}
	code, out, _ = run(t, ToolCopilot, "preToolUse", `{"toolName":"bash","toolArgs":{"command":"cat .env"}}`)
	m = parseJSON(t, out)
	if code != 0 || m["permissionDecision"] != "deny" {
		t.Errorf("deny shell: code=%d out=%q", code, out)
	}
	code, out, _ = run(t, ToolCopilot, "preToolUse", `{"toolName":"bash","toolArgs":{"command":"npm test"}}`)
	if code != 0 || out != "" {
		t.Errorf("allow: code=%d out=%q", code, out)
	}
}

func TestRunFailsOpen(t *testing.T) {
	for _, tool := range Tools() {
		for _, payload := range []string{"", "not json", "[1,2]", "{", `{"tool_name":"Read"}`} {
			code, out, errOut := run(t, tool, "PreToolUse", payload)
			if code != 0 || out != "" || errOut != "" {
				t.Errorf("%s garbage %q: code=%d out=%q err=%q", tool, payload, code, out, errOut)
			}
		}
	}
	if code, out, _ := run(t, "unknown", "PreToolUse", `{"tool_input":{"file_path":".env"}}`); code != 0 || out != "" {
		t.Errorf("unknown tool: code=%d out=%q", code, out)
	}
	if code, out, _ := run(t, ToolClaudeCode, "NoSuchEvent", `{"tool_input":{"file_path":".env"}}`); code != 0 || out != "" {
		t.Errorf("unknown event: code=%d out=%q", code, out)
	}
}

func TestCoverageTable(t *testing.T) {
	table := CoverageTable()
	if len(table) != len(Tools()) {
		t.Fatalf("coverage has %d rows, want %d", len(table), len(Tools()))
	}
	for i, tool := range Tools() {
		c := table[i]
		if c.Tool != tool || c.ConfigPath == "" || len(c.Events) == 0 || c.Notes == "" {
			t.Errorf("incomplete coverage row: %+v", c)
		}
	}
}

func countMarker(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.Count(string(data), hookMarker)
}

func TestInstallUninstallRoundTrip(t *testing.T) {
	home := t.TempDir()
	bin := "/opt/bin/agentleaks"
	for _, tool := range Tools() {
		spec, _ := specFor(tool)
		if err := os.MkdirAll(filepath.Join(home, spec.dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Pre-existing content that must survive.
	existing := map[string]string{
		filepath.Join(home, ".claude", "settings.json"): `{"model":"opus","hooks":{"Stop":[{"hooks":[{"type":"command","command":"say done"}]}]}}`,
		filepath.Join(home, ".gemini", "settings.json"): `{"theme":"dark"}`,
		filepath.Join(home, ".cursor", "hooks.json"):    `{"version":1,"hooks":{"stop":[{"command":"./notify.sh"}]}}`,
	}
	for path, content := range existing {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	opts := InstallOptions{Home: home, Binary: bin}
	results := Install(opts)
	if len(results) != len(Tools()) {
		t.Fatalf("got %d results", len(results))
	}
	for _, r := range results {
		if r.Err != nil || r.Action != "installed" {
			t.Errorf("%s: action=%s err=%v", r.Tool, r.Action, r.Err)
		}
		if !strings.HasPrefix(r.Path, home) {
			t.Errorf("%s wrote outside home: %s", r.Tool, r.Path)
		}
	}
	expected := map[string]int{
		ToolClaudeCode: 2, ToolCodex: 1, ToolCursor: 2, ToolGemini: 1, ToolCopilot: 1,
	}
	for _, r := range results {
		if n := countMarker(t, r.Path); n != expected[r.Tool] {
			t.Errorf("%s: marker count %d, want %d", r.Tool, n, expected[r.Tool])
		}
	}

	// Second install is a no-op.
	for _, r := range Install(opts) {
		if r.Action != "already-installed" || r.Err != nil {
			t.Errorf("%s second install: action=%s err=%v", r.Tool, r.Action, r.Err)
		}
		if n := countMarker(t, r.Path); n != expected[r.Tool] {
			t.Errorf("%s duplicated: marker count %d", r.Tool, n)
		}
	}

	// Unrelated keys survive and files are valid JSON.
	claude := parseFile(t, filepath.Join(home, ".claude", "settings.json"))
	if claude["model"] != "opus" {
		t.Error("claude settings lost model key")
	}
	if hooks, _ := claude["hooks"].(map[string]any); hooks["Stop"] == nil || hooks["PreToolUse"] == nil || hooks["PostToolUse"] == nil {
		t.Errorf("claude hooks incomplete: %v", hooks)
	}
	gemini := parseFile(t, filepath.Join(home, ".gemini", "settings.json"))
	if gemini["theme"] != "dark" {
		t.Error("gemini settings lost theme")
	}
	cursor := parseFile(t, filepath.Join(home, ".cursor", "hooks.json"))
	if cursor["version"] != float64(1) {
		t.Error("cursor version missing")
	}
	if hooks, _ := cursor["hooks"].(map[string]any); hooks["stop"] == nil || hooks["beforeReadFile"] == nil || hooks["beforeShellExecution"] == nil {
		t.Errorf("cursor hooks incomplete: %v", hooks)
	}
	codex := parseFile(t, filepath.Join(home, ".codex", "hooks.json"))
	if hooks, _ := codex["hooks"].(map[string]any); hooks["PreToolUse"] == nil {
		t.Errorf("codex hooks incomplete: %v", hooks)
	}
	copilot := parseFile(t, filepath.Join(home, ".copilot", "hooks", "agentleaks.json"))
	if hooks, _ := copilot["hooks"].(map[string]any); hooks["preToolUse"] == nil || copilot["version"] != float64(1) {
		t.Errorf("copilot hooks incomplete: %v", copilot)
	}

	// Uninstall removes only ours.
	for _, r := range Uninstall(opts) {
		if r.Action != "removed" || r.Err != nil {
			t.Errorf("%s uninstall: action=%s err=%v", r.Tool, r.Action, r.Err)
		}
	}
	claude = parseFile(t, filepath.Join(home, ".claude", "settings.json"))
	if claude["model"] != "opus" {
		t.Error("claude settings lost model key after uninstall")
	}
	if hooks, _ := claude["hooks"].(map[string]any); hooks["Stop"] == nil || hooks["PreToolUse"] != nil {
		t.Errorf("claude hooks after uninstall: %v", hooks)
	}
	if n := countMarker(t, filepath.Join(home, ".claude", "settings.json")); n != 0 {
		t.Errorf("claude marker still present %d", n)
	}
	gemini = parseFile(t, filepath.Join(home, ".gemini", "settings.json"))
	if _, has := gemini["hooks"]; has {
		t.Error("gemini should drop empty hooks key")
	}
	cursor = parseFile(t, filepath.Join(home, ".cursor", "hooks.json"))
	if hooks, _ := cursor["hooks"].(map[string]any); hooks["stop"] == nil || len(hooks) != 1 {
		t.Errorf("cursor hooks after uninstall: %v", hooks)
	}
	if _, err := os.Stat(filepath.Join(home, ".copilot", "hooks", "agentleaks.json")); !os.IsNotExist(err) {
		t.Error("copilot owned file should be removed")
	}
	for _, r := range Uninstall(opts) {
		if r.Action != "not-installed" {
			t.Errorf("%s second uninstall: action=%s", r.Tool, r.Action)
		}
	}
}

func parseFile(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return parseJSON(t, string(data))
}

func TestInstallDryRunAndSkip(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	results := Install(InstallOptions{Home: home, Binary: "/opt/bin/agentleaks", DryRun: true})
	for _, r := range results {
		switch r.Tool {
		case ToolClaudeCode:
			if r.Action != "would-install" {
				t.Errorf("claude dry run: %s", r.Action)
			}
		default:
			if r.Action != "skipped-not-found" {
				t.Errorf("%s: %s, want skipped-not-found", r.Tool, r.Action)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Error("dry run wrote a file")
	}
	entries, _ := os.ReadDir(home)
	if len(entries) != 1 {
		t.Errorf("dry run created directories: %v", entries)
	}

	// Force installs into a missing directory, restricted to one tool.
	results = Install(InstallOptions{Home: home, Binary: "/opt/bin/agentleaks", Tools: []string{ToolCodex}, Force: true})
	if len(results) != 1 || results[0].Action != "installed" {
		t.Errorf("force: %+v", results)
	}
	if n := countMarker(t, filepath.Join(home, ".codex", "hooks.json")); n != 1 {
		t.Errorf("codex marker count %d", n)
	}
	results = Uninstall(InstallOptions{Home: home, Tools: []string{ToolCodex}, DryRun: true})
	if results[0].Action != "would-remove" {
		t.Errorf("dry uninstall: %s", results[0].Action)
	}
	if n := countMarker(t, filepath.Join(home, ".codex", "hooks.json")); n != 1 {
		t.Error("dry run uninstall changed the file")
	}
}

func TestInstallRefusesInvalidJSON(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := Install(InstallOptions{Home: home, Binary: "/opt/bin/agentleaks", Tools: []string{ToolClaudeCode}})
	if results[0].Err == nil || results[0].Action != "error" {
		t.Errorf("expected error, got %+v", results[0])
	}
	data, _ := os.ReadFile(path)
	if string(data) != "{ not json" {
		t.Error("invalid file was modified")
	}
}

func TestBinaryWithSpacesIsQuoted(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	Install(InstallOptions{Home: home, Binary: "/Applications/My Tools/agentleaks", Tools: []string{ToolCodex}})
	data, _ := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
	if !strings.Contains(string(data), `\"/Applications/My Tools/agentleaks\" hook codex PreToolUse`) {
		t.Errorf("binary not quoted: %s", data)
	}
}
