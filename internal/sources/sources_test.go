package sources

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

type expect struct {
	rel        string
	tool       string
	kind       Kind
	credential bool
}

func TestDiscoverDarwin(t *testing.T) {
	home := t.TempDir()
	appSupport := filepath.Join("Library", "Application Support")
	vscode := filepath.Join(appSupport, "Code", "User", "globalStorage")
	expects := []expect{
		{".claude/projects/p1/a.jsonl", "claude-code", KindJSONL, false},
		{".claude/history.jsonl", "claude-code", KindJSONL, false},
		{".claude.json", "claude-code", KindJSON, false},
		{".codex/sessions/2026/09/29/rollout-x.jsonl", "codex", KindJSONL, false},
		{".codex/history.jsonl", "codex", KindJSONL, false},
		{".codex/auth.json", "codex", KindJSON, true},
		{filepath.Join(appSupport, "Cursor", "User", "globalStorage", "state.vscdb"), "cursor", KindSQLite, false},
		{filepath.Join(appSupport, "Cursor", "User", "workspaceStorage", "h1", "state.vscdb"), "cursor", KindSQLite, false},
		{".gemini/tmp/h/chats/session-1.json", "gemini", KindJSON, false},
		{filepath.Join(vscode, "saoudrizwan.claude-dev", "tasks", "1", "api_conversation_history.json"), "cline", KindJSON, false},
		{filepath.Join(vscode, "rooveterinaryinc.roo-cline", "tasks", "1", "ui_messages.json"), "roo-code", KindJSON, false},
		{".local/share/opencode/storage/session/x/y.json", "opencode", KindJSON, false},
		{".copilot/session-state/s1/events.jsonl", "copilot", KindJSONL, false},
		{filepath.Join(appSupport, "Claude", "claude_desktop_config.json"), "claude-desktop", KindJSON, false},
		{".codeium/windsurf/mcp_config.json", "windsurf", KindJSON, false},
		{".continue/config.yaml", "continue", KindText, false},
		{"Desktop/proj/.aider.chat.history.md", "aider", KindText, false},
		{"Desktop/proj/.mcp.json", "claude-code", KindJSON, false},
		{"Desktop/proj/.cursor/mcp.json", "cursor", KindJSON, false},
	}
	for _, e := range expects {
		touch(t, filepath.Join(home, e.rel))
	}
	env := Env{
		Home: home, GOOS: "darwin",
		XDGConfig: filepath.Join(home, ".config"), XDGData: filepath.Join(home, ".local", "share"),
		RepoRoots: []string{filepath.Join(home, "Desktop")},
	}
	targets, statuses := Discover(env, nil)
	byPath := map[string][]Target{}
	for _, tg := range targets {
		byPath[tg.Path] = append(byPath[tg.Path], tg)
	}
	for _, e := range expects {
		p := filepath.Join(home, e.rel)
		got := byPath[p]
		if len(got) != 1 {
			t.Errorf("%s: found %d times, want exactly once", e.rel, len(got))
			continue
		}
		tg := got[0]
		if tg.Tool != e.tool || tg.Kind != e.kind || tg.Credential != e.credential {
			t.Errorf("%s: tool=%s kind=%s credential=%v, want %s %s %v", e.rel, tg.Tool, tg.Kind, tg.Credential, e.tool, e.kind, e.credential)
		}
		if tg.Size == 0 || tg.ModTime.IsZero() || tg.ToolName == "" || tg.Label == "" {
			t.Errorf("%s: incomplete target %+v", e.rel, tg)
		}
	}
	if len(targets) != len(expects) {
		t.Errorf("discovered %d targets, want %d", len(targets), len(expects))
	}
	found := map[string]bool{}
	for _, s := range statuses {
		found[s.Tool] = s.Found
	}
	for _, e := range expects {
		if !found[e.tool] {
			t.Errorf("tool %s should be reported as found", e.tool)
		}
	}
	if found["vscode-copilot-chat"] {
		t.Error("vscode-copilot-chat has no files and must not be found")
	}
	if len(statuses) != len(Registry) {
		t.Errorf("got %d statuses, want one per registry entry (%d)", len(statuses), len(Registry))
	}

	only, onlyStatus := Discover(env, []string{"codex", "aider"})
	for _, tg := range only {
		if tg.Tool != "codex" && tg.Tool != "aider" {
			t.Errorf("only filter leaked tool %s", tg.Tool)
		}
	}
	if len(only) != 4 {
		t.Errorf("only filter returned %d targets, want 4", len(only))
	}
	if len(onlyStatus) != 2 {
		t.Errorf("only filter returned %d statuses, want 2", len(onlyStatus))
	}
}

func TestDiscoverLinux(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, ".config")
	cursor := filepath.Join(cfg, "Cursor", "User", "globalStorage", "state.vscdb")
	desktop := filepath.Join(cfg, "Claude", "claude_desktop_config.json")
	cline := filepath.Join(cfg, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "tasks", "1", "ui_messages.json")
	for _, p := range []string{cursor, desktop, cline} {
		touch(t, p)
	}
	env := Env{Home: home, GOOS: "linux", XDGConfig: cfg, XDGData: filepath.Join(home, ".local", "share"), RepoRoots: []string{}}
	targets, _ := Discover(env, nil)
	want := map[string]string{cursor: "cursor", desktop: "claude-desktop", cline: "cline"}
	if len(targets) != len(want) {
		t.Fatalf("got %d targets: %+v", len(targets), targets)
	}
	for _, tg := range targets {
		if want[tg.Path] != tg.Tool {
			t.Errorf("%s resolved to %s", tg.Path, tg.Tool)
		}
	}
}

func TestDiscoverWindows(t *testing.T) {
	home := t.TempDir()
	appdata := filepath.Join(home, "AppData", "Roaming")
	cursor := filepath.Join(appdata, "Cursor", "User", "globalStorage", "state.vscdb")
	desktop := filepath.Join(appdata, "Claude", "claude_desktop_config.json")
	windsurf := filepath.Join(appdata, "devin", "mcp_config.json")
	for _, p := range []string{cursor, desktop, windsurf} {
		touch(t, p)
	}
	env := Env{Home: home, GOOS: "windows", AppData: appdata, RepoRoots: []string{}}
	targets, _ := Discover(env, nil)
	want := map[string]string{cursor: "cursor", desktop: "claude-desktop", windsurf: "windsurf"}
	if len(targets) != len(want) {
		t.Fatalf("got %d targets: %+v", len(targets), targets)
	}
	for _, tg := range targets {
		if want[tg.Path] != tg.Tool {
			t.Errorf("%s resolved to %s", tg.Path, tg.Tool)
		}
	}
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func TestExpand(t *testing.T) {
	base := t.TempDir()
	zero := filepath.Join(base, "a", "x.txt")
	deep := filepath.Join(base, "a", "b", "c", "y.txt")
	touch(t, zero)
	touch(t, deep)
	touch(t, filepath.Join(base, "a", "b", "skip.md"))
	got := sorted(expand(base, "a/**/*.txt", 0))
	want := sorted([]string{zero, deep})
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("** expansion = %v, want %v", got, want)
	}

	// The .. segment is used by the VS Code workspaceStorage pattern.
	user := filepath.Join(base, "User")
	session := filepath.Join(user, "workspaceStorage", "h", "chatSessions", "s.jsonl")
	touch(t, session)
	got = expand(filepath.Join(user, "globalStorage"), "../workspaceStorage/*/chatSessions/*.jsonl", 0)
	if len(got) != 1 || got[0] != session {
		t.Errorf(".. expansion = %v, want [%s]", got, session)
	}

	// A symlinked directory is not followed by ** recursion.
	other := filepath.Join(base, "other")
	touch(t, filepath.Join(other, "z.txt"))
	if err := os.Symlink(other, filepath.Join(base, "a", "link")); err != nil {
		t.Skip("symlinks not supported here")
	}
	got = expand(base, "a/**/*.txt", 0)
	for _, p := range got {
		if filepath.Base(filepath.Dir(p)) == "link" {
			t.Errorf("** followed a symlinked directory: %s", p)
		}
	}

	// Directories are only returned when asked, which root hints rely on.
	if got := expand(base, "a", 0); len(got) != 0 {
		t.Errorf("directory returned without allowDirs: %v", got)
	}
	if got := expand(base, "a", 1); len(got) != 1 {
		t.Errorf("directory not returned with allowDirs: %v", got)
	}
	if got := expand(base, "missing/*.txt", 0); len(got) != 0 {
		t.Errorf("missing base produced %v", got)
	}
}

func TestRepoDirs(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a/b/c/d", "node_modules/pkg", ".git/objects", "a/node_modules/x"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := Env{RepoRoots: []string{root}, RepoDepth: 2}
	got := env.repoDirs()
	has := map[string]bool{}
	for _, d := range got {
		has[d] = true
	}
	for _, want := range []string{root, filepath.Join(root, "a"), filepath.Join(root, "a", "b")} {
		if !has[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	for _, no := range []string{filepath.Join(root, "a", "b", "c"), filepath.Join(root, "node_modules"), filepath.Join(root, ".git"), filepath.Join(root, "a", "node_modules")} {
		if has[no] {
			t.Errorf("%s should not be listed", no)
		}
	}
	if got := (Env{RepoRoots: []string{filepath.Join(root, "missing")}, RepoDepth: 2}).repoDirs(); len(got) != 0 {
		t.Errorf("missing root produced %v", got)
	}
}

func TestKindForPath(t *testing.T) {
	cases := map[string]Kind{
		"a.jsonl": KindJSONL, "b.ndjson": KindJSONL, "c.json": KindJSON, "d.JSON": KindJSON,
		"e.db": KindSQLite, "f.sqlite": KindSQLite, "g.sqlite3": KindSQLite, "state.vscdb": KindSQLite,
		"h.md": KindText, "config.toml": KindText, "noext": KindText,
	}
	for p, want := range cases {
		if got := KindForPath(p); got != want {
			t.Errorf("KindForPath(%q) = %s, want %s", p, got, want)
		}
	}
}

func TestShorten(t *testing.T) {
	home := "/Users/someone"
	if got := Shorten(home, home+"/.claude/x"); got != "~/.claude/x" {
		t.Errorf("got %q", got)
	}
	if got := Shorten(home, "/other/path"); got != "/other/path" {
		t.Errorf("got %q", got)
	}
	if got := Shorten("", home); got != home {
		t.Errorf("got %q", got)
	}
}

func TestPatternDisplay(t *testing.T) {
	cases := map[string]string{
		"home":      "~/g",
		"appdata":   "%APPDATA%/g",
		"xdgconfig": "~/.config/g",
		"xdgdata":   "~/.local/share/g",
		"vscode":    "<vscode globalStorage>/g",
		"repo":      "<repo>/g",
		"other":     "g",
	}
	for base, want := range cases {
		if got := (Pattern{Base: base, Glob: "g"}).Display(); got != want {
			t.Errorf("Display(%s) = %q, want %q", base, got, want)
		}
	}
}

func TestRegistryConsistency(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range Registry {
		if seen[tool.ID] {
			t.Errorf("duplicate tool id %s", tool.ID)
		}
		seen[tool.ID] = true
		if len(tool.Patterns) == 0 || len(tool.RootHint) == 0 {
			t.Errorf("%s has no patterns or root hints", tool.ID)
		}
		for _, p := range tool.Patterns {
			if p.Kind == "" || p.Label == "" || p.Glob == "" {
				t.Errorf("%s pattern %+v is incomplete", tool.ID, p)
			}
		}
		if got, ok := Lookup(tool.ID); !ok || got.Name != tool.Name {
			t.Errorf("Lookup(%s) failed", tool.ID)
		}
	}
	if _, ok := Lookup("nope"); ok {
		t.Error("Lookup of unknown id succeeded")
	}
	if len(ToolIDs()) != len(Registry) {
		t.Error("ToolIDs length mismatch")
	}
}

func TestEnvFill(t *testing.T) {
	e := Env{Home: "/h", GOOS: "linux"}.Fill()
	if e.RepoDepth != 4 {
		t.Errorf("RepoDepth = %d", e.RepoDepth)
	}
	if e.XDGConfig == "" || e.XDGData == "" || e.AppData == "" {
		t.Errorf("Fill left paths empty: %+v", e)
	}
	if e.RepoRoots == nil {
		// A home with no project folders yields an empty, non-nil default.
		t.Log("RepoRoots nil for a home without project folders, acceptable")
	}
}
