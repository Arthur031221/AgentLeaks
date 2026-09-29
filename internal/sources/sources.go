// Package sources knows where every supported AI coding tool keeps its
// transcripts, history and configuration on disk, and discovers which of
// those files exist on this machine.
package sources

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Kind tells the scanner how to read a file.
type Kind string

const (
	KindJSONL  Kind = "jsonl"
	KindJSON   Kind = "json"
	KindText   Kind = "text"
	KindSQLite Kind = "sqlite"
)

// Env describes the machine being scanned. Zero values are filled from the
// current process environment by Fill.
type Env struct {
	Home      string
	GOOS      string
	AppData   string // Windows %APPDATA%
	XDGConfig string // Linux, defaults to ~/.config
	XDGData   string // Linux, defaults to ~/.local/share
	RepoRoots []string
	RepoDepth int
}

// Fill completes an Env from the process environment.
func (e Env) Fill() Env {
	if e.GOOS == "" {
		e.GOOS = runtime.GOOS
	}
	if e.Home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			e.Home = h
		}
	}
	if e.AppData == "" {
		e.AppData = os.Getenv("APPDATA")
		if e.AppData == "" && e.Home != "" {
			e.AppData = filepath.Join(e.Home, "AppData", "Roaming")
		}
	}
	if e.XDGConfig == "" {
		e.XDGConfig = os.Getenv("XDG_CONFIG_HOME")
		if e.XDGConfig == "" {
			e.XDGConfig = filepath.Join(e.Home, ".config")
		}
	}
	if e.XDGData == "" {
		e.XDGData = os.Getenv("XDG_DATA_HOME")
		if e.XDGData == "" {
			e.XDGData = filepath.Join(e.Home, ".local", "share")
		}
	}
	if e.RepoDepth == 0 {
		e.RepoDepth = 4
	}
	if e.RepoRoots == nil {
		e.RepoRoots = defaultRepoRoots(e.Home)
	}
	return e
}

func defaultRepoRoots(home string) []string {
	var roots []string
	for _, d := range []string{"Desktop", "Documents", "Projects", "projects", "code", "src", "dev", "work", "repos", "git", "workspace", "www"} {
		p := filepath.Join(home, d)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			roots = append(roots, p)
		}
	}
	return roots
}

// Pattern is one glob relative to a base directory chosen by Base.
type Pattern struct {
	Base  string // "home", "appdata", "xdgconfig", "xdgdata", "vscode", "repo"
	Glob  string // may contain * ? and ** (directory wildcard)
	Kind  Kind
	Label string
	// Credential marks the tool's own credential store. It is scanned and
	// reported, but fix skips it unless asked, because redacting it logs the
	// user out of the tool.
	Credential bool
	OS         []string // restrict to these GOOS values, empty means all
}

// Tool is one supported source.
type Tool struct {
	ID       string
	Name     string
	Patterns []Pattern
	// RootHint names the directory whose presence means the tool is installed.
	RootHint []Pattern
}

// Target is one file to scan.
type Target struct {
	Tool       string
	ToolName   string
	Label      string
	Kind       Kind
	Path       string
	Size       int64
	ModTime    time.Time
	Credential bool
}

// Status reports whether a tool was found.
type Status struct {
	Tool     string `json:"tool"`
	Name     string `json:"name"`
	Found    bool   `json:"found"`
	Files    int    `json:"files"`
	Bytes    int64  `json:"bytes"`
	RootPath string `json:"root,omitempty"`
}

var mac = []string{"darwin"}
var linux = []string{"linux"}
var win = []string{"windows"}

// vscodeStores lists the VS Code family user data directories that host
// Cline, Roo Code and Copilot Chat extension storage.
var vscodeStores = []string{"Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"}

// Registry is the ordered list of supported tools.
var Registry = []Tool{
	{
		ID: "claude-code", Name: "Claude Code",
		RootHint: []Pattern{{Base: "home", Glob: ".claude"}, {Base: "home", Glob: ".claude.json"}},
		Patterns: []Pattern{
			{Base: "home", Glob: ".claude/projects/**/*.jsonl", Kind: KindJSONL, Label: "session transcript"},
			{Base: "home", Glob: ".claude/history.jsonl", Kind: KindJSONL, Label: "prompt history"},
			{Base: "home", Glob: ".claude.json", Kind: KindJSON, Label: "app state and MCP config"},
			{Base: "home", Glob: ".claude/settings.json", Kind: KindJSON, Label: "settings"},
			{Base: "home", Glob: ".claude/settings.local.json", Kind: KindJSON, Label: "settings"},
			{Base: "home", Glob: ".claude/file-history/**/*", Kind: KindText, Label: "edited file snapshot"},
			{Base: "home", Glob: ".claude/paste-cache/*.txt", Kind: KindText, Label: "pasted text"},
			{Base: "home", Glob: ".claude/shell-snapshots/*.sh", Kind: KindText, Label: "shell snapshot"},
			{Base: "home", Glob: ".claude/.credentials.json", Kind: KindJSON, Label: "OAuth credentials", Credential: true},
			{Base: "home", Glob: ".claude/sessions/*.key", Kind: KindText, Label: "session key", Credential: true},
			{Base: "repo", Glob: ".mcp.json", Kind: KindJSON, Label: "project MCP config"},
			{Base: "repo", Glob: ".claude/settings.json", Kind: KindJSON, Label: "project settings"},
			{Base: "repo", Glob: ".claude/settings.local.json", Kind: KindJSON, Label: "project settings"},
		},
	},
	{
		ID: "codex", Name: "Codex",
		RootHint: []Pattern{{Base: "home", Glob: ".codex"}},
		Patterns: []Pattern{
			{Base: "home", Glob: ".codex/sessions/**/*.jsonl", Kind: KindJSONL, Label: "session rollout"},
			{Base: "home", Glob: ".codex/archived_sessions/**/*.jsonl", Kind: KindJSONL, Label: "archived rollout"},
			{Base: "home", Glob: ".codex/history.jsonl", Kind: KindJSONL, Label: "prompt history"},
			{Base: "home", Glob: ".codex/config.toml", Kind: KindText, Label: "config"},
			{Base: "home", Glob: ".codex/hooks.json", Kind: KindJSON, Label: "hooks"},
			{Base: "home", Glob: ".codex/log/*.log", Kind: KindText, Label: "log"},
			{Base: "home", Glob: ".codex/auth.json", Kind: KindJSON, Label: "auth tokens", Credential: true},
			{Base: "repo", Glob: ".codex/config.toml", Kind: KindText, Label: "project config"},
		},
	},
	{
		ID: "cursor", Name: "Cursor",
		RootHint: []Pattern{
			{Base: "home", Glob: "Library/Application Support/Cursor", OS: mac},
			{Base: "xdgconfig", Glob: "Cursor", OS: linux},
			{Base: "appdata", Glob: "Cursor", OS: win},
			{Base: "home", Glob: ".cursor"},
		},
		Patterns: []Pattern{
			{Base: "home", Glob: "Library/Application Support/Cursor/User/globalStorage/state.vscdb", Kind: KindSQLite, Label: "global chat store", OS: mac},
			{Base: "home", Glob: "Library/Application Support/Cursor/User/workspaceStorage/*/state.vscdb", Kind: KindSQLite, Label: "workspace chat store", OS: mac},
			{Base: "xdgconfig", Glob: "Cursor/User/globalStorage/state.vscdb", Kind: KindSQLite, Label: "global chat store", OS: linux},
			{Base: "xdgconfig", Glob: "Cursor/User/workspaceStorage/*/state.vscdb", Kind: KindSQLite, Label: "workspace chat store", OS: linux},
			{Base: "appdata", Glob: "Cursor/User/globalStorage/state.vscdb", Kind: KindSQLite, Label: "global chat store", OS: win},
			{Base: "appdata", Glob: "Cursor/User/workspaceStorage/*/state.vscdb", Kind: KindSQLite, Label: "workspace chat store", OS: win},
			{Base: "home", Glob: ".cursor/mcp.json", Kind: KindJSON, Label: "MCP config"},
			{Base: "home", Glob: ".cursor/hooks.json", Kind: KindJSON, Label: "hooks"},
			{Base: "repo", Glob: ".cursor/mcp.json", Kind: KindJSON, Label: "project MCP config"},
		},
	},
	{
		ID: "gemini", Name: "Gemini CLI",
		RootHint: []Pattern{{Base: "home", Glob: ".gemini"}},
		Patterns: []Pattern{
			{Base: "home", Glob: ".gemini/tmp/*/chats/*.json", Kind: KindJSON, Label: "chat session"},
			{Base: "home", Glob: ".gemini/tmp/*/chats/*.jsonl", Kind: KindJSONL, Label: "chat session"},
			{Base: "home", Glob: ".gemini/tmp/*/checkpoints/**/*", Kind: KindText, Label: "checkpoint"},
			{Base: "home", Glob: ".gemini/tmp/*/shell_history", Kind: KindText, Label: "shell history"},
			{Base: "home", Glob: ".gemini/history/**/*", Kind: KindText, Label: "history"},
			{Base: "home", Glob: ".gemini/settings.json", Kind: KindJSON, Label: "settings and MCP config"},
			{Base: "home", Glob: ".gemini/.env", Kind: KindText, Label: "env file"},
			{Base: "home", Glob: ".gemini/oauth_creds.json", Kind: KindJSON, Label: "OAuth credentials", Credential: true},
			{Base: "home", Glob: ".gemini/mcp-oauth-tokens.json", Kind: KindJSON, Label: "MCP OAuth tokens", Credential: true},
			{Base: "repo", Glob: ".gemini/settings.json", Kind: KindJSON, Label: "project settings"},
		},
	},
	{
		ID: "cline", Name: "Cline",
		RootHint: []Pattern{{Base: "vscode", Glob: "saoudrizwan.claude-dev"}},
		Patterns: []Pattern{
			{Base: "vscode", Glob: "saoudrizwan.claude-dev/tasks/*/api_conversation_history.json", Kind: KindJSON, Label: "task conversation"},
			{Base: "vscode", Glob: "saoudrizwan.claude-dev/tasks/*/ui_messages.json", Kind: KindJSON, Label: "task UI messages"},
			{Base: "vscode", Glob: "saoudrizwan.claude-dev/tasks/*/context_history.json", Kind: KindJSON, Label: "task context"},
			{Base: "vscode", Glob: "saoudrizwan.claude-dev/settings/cline_mcp_settings.json", Kind: KindJSON, Label: "MCP settings"},
			{Base: "vscode", Glob: "saoudrizwan.claude-dev/state/taskHistory.json", Kind: KindJSON, Label: "task history"},
			{Base: "vscode", Glob: "saoudrizwan.claude-dev/secrets.json", Kind: KindJSON, Label: "secrets store", Credential: true},
		},
	},
	{
		ID: "roo-code", Name: "Roo Code",
		RootHint: []Pattern{{Base: "vscode", Glob: "rooveterinaryinc.roo-cline"}},
		Patterns: []Pattern{
			{Base: "vscode", Glob: "rooveterinaryinc.roo-cline/tasks/*/api_conversation_history.json", Kind: KindJSON, Label: "task conversation"},
			{Base: "vscode", Glob: "rooveterinaryinc.roo-cline/tasks/*/ui_messages.json", Kind: KindJSON, Label: "task UI messages"},
			{Base: "vscode", Glob: "rooveterinaryinc.roo-cline/settings/mcp_settings.json", Kind: KindJSON, Label: "MCP settings"},
		},
	},
	{
		ID: "opencode", Name: "OpenCode",
		RootHint: []Pattern{{Base: "xdgdata", Glob: "opencode"}, {Base: "xdgconfig", Glob: "opencode"}},
		Patterns: []Pattern{
			{Base: "xdgdata", Glob: "opencode/storage/**/*.json", Kind: KindJSON, Label: "session storage"},
			{Base: "xdgdata", Glob: "opencode/*.db", Kind: KindSQLite, Label: "session database"},
			{Base: "xdgdata", Glob: "opencode/log/*.log", Kind: KindText, Label: "log"},
			{Base: "xdgdata", Glob: "opencode/auth.json", Kind: KindJSON, Label: "auth tokens", Credential: true},
			{Base: "xdgconfig", Glob: "opencode/opencode.json", Kind: KindJSON, Label: "config"},
			{Base: "repo", Glob: "opencode.json", Kind: KindJSON, Label: "project config"},
		},
	},
	{
		ID: "aider", Name: "Aider",
		RootHint: []Pattern{{Base: "home", Glob: ".aider*"}, {Base: "repo", Glob: ".aider.chat.history.md"}},
		Patterns: []Pattern{
			{Base: "repo", Glob: ".aider.chat.history.md", Kind: KindText, Label: "chat history"},
			{Base: "repo", Glob: ".aider.input.history", Kind: KindText, Label: "input history"},
			{Base: "repo", Glob: ".aider.llm.history", Kind: KindText, Label: "LLM history"},
			{Base: "home", Glob: ".aider.chat.history.md", Kind: KindText, Label: "chat history"},
			{Base: "home", Glob: ".aider.input.history", Kind: KindText, Label: "input history"},
			{Base: "home", Glob: ".aider.conf.yml", Kind: KindText, Label: "config"},
			{Base: "home", Glob: ".aider/**/*", Kind: KindText, Label: "aider data"},
		},
	},
	{
		ID: "copilot", Name: "GitHub Copilot CLI",
		RootHint: []Pattern{{Base: "home", Glob: ".copilot"}},
		Patterns: []Pattern{
			{Base: "home", Glob: ".copilot/session-state/**/*.jsonl", Kind: KindJSONL, Label: "session events"},
			{Base: "home", Glob: ".copilot/session-state/**/*.json", Kind: KindJSON, Label: "session state"},
			{Base: "home", Glob: ".copilot/session-store.db", Kind: KindSQLite, Label: "session database"},
			{Base: "home", Glob: ".copilot/command-history-state/**/*", Kind: KindText, Label: "command history"},
			{Base: "home", Glob: ".copilot/logs/*.log", Kind: KindText, Label: "log"},
			{Base: "home", Glob: ".copilot/mcp-config.json", Kind: KindJSON, Label: "MCP config"},
			{Base: "home", Glob: ".copilot/settings.json", Kind: KindJSON, Label: "settings"},
			{Base: "home", Glob: ".copilot/providers.json", Kind: KindJSON, Label: "BYOK providers"},
			{Base: "home", Glob: ".copilot/config.json", Kind: KindJSON, Label: "auth state", Credential: true},
			{Base: "home", Glob: ".copilot/mcp-secrets/**/*", Kind: KindText, Label: "MCP secrets", Credential: true},
			{Base: "home", Glob: ".copilot/mcp-oauth-config/**/*", Kind: KindText, Label: "MCP OAuth", Credential: true},
		},
	},
	{
		ID: "vscode-copilot-chat", Name: "VS Code Copilot Chat",
		RootHint: []Pattern{{Base: "vscode", Glob: "github.copilot-chat"}},
		Patterns: []Pattern{
			{Base: "vscode", Glob: "emptyWindowChatSessions/*.jsonl", Kind: KindJSONL, Label: "chat session"},
			{Base: "vscode", Glob: "../workspaceStorage/*/chatSessions/*.jsonl", Kind: KindJSONL, Label: "workspace chat session"},
			{Base: "vscode", Glob: "github.copilot-chat/session-store.db", Kind: KindSQLite, Label: "agent session store"},
		},
	},
	{
		ID: "claude-desktop", Name: "Claude Desktop",
		RootHint: []Pattern{
			{Base: "home", Glob: "Library/Application Support/Claude", OS: mac},
			{Base: "appdata", Glob: "Claude", OS: win},
			{Base: "xdgconfig", Glob: "Claude", OS: linux},
		},
		Patterns: []Pattern{
			{Base: "home", Glob: "Library/Application Support/Claude/claude_desktop_config.json", Kind: KindJSON, Label: "MCP config", OS: mac},
			{Base: "appdata", Glob: "Claude/claude_desktop_config.json", Kind: KindJSON, Label: "MCP config", OS: win},
			{Base: "xdgconfig", Glob: "Claude/claude_desktop_config.json", Kind: KindJSON, Label: "MCP config", OS: linux},
		},
	},
	{
		ID: "windsurf", Name: "Windsurf",
		RootHint: []Pattern{{Base: "home", Glob: ".codeium/windsurf"}, {Base: "xdgconfig", Glob: "devin"}, {Base: "appdata", Glob: "devin", OS: win}},
		Patterns: []Pattern{
			{Base: "home", Glob: ".codeium/windsurf/mcp_config.json", Kind: KindJSON, Label: "MCP config"},
			{Base: "xdgconfig", Glob: "devin/mcp_config.json", Kind: KindJSON, Label: "MCP config"},
			{Base: "appdata", Glob: "devin/mcp_config.json", Kind: KindJSON, Label: "MCP config", OS: win},
		},
	},
	{
		ID: "continue", Name: "Continue",
		RootHint: []Pattern{{Base: "home", Glob: ".continue"}},
		Patterns: []Pattern{
			{Base: "home", Glob: ".continue/config.yaml", Kind: KindText, Label: "config"},
			{Base: "home", Glob: ".continue/config.json", Kind: KindJSON, Label: "legacy config"},
			{Base: "home", Glob: ".continue/config.ts", Kind: KindText, Label: "config"},
			{Base: "home", Glob: ".continue/.env", Kind: KindText, Label: "env file"},
			{Base: "home", Glob: ".continue/sessions/*.json", Kind: KindJSON, Label: "chat session"},
			{Base: "repo", Glob: ".continue/config.yaml", Kind: KindText, Label: "project config"},
		},
	},
}

// ToolIDs returns the registry ids in order.
func ToolIDs() []string {
	ids := make([]string, 0, len(Registry))
	for _, t := range Registry {
		ids = append(ids, t.ID)
	}
	return ids
}

// Lookup returns the tool with the given id.
func Lookup(id string) (Tool, bool) {
	for _, t := range Registry {
		if t.ID == id {
			return t, true
		}
	}
	return Tool{}, false
}

func (p Pattern) appliesTo(goos string) bool {
	if len(p.OS) == 0 {
		return true
	}
	for _, o := range p.OS {
		if o == goos {
			return true
		}
	}
	return false
}

// bases returns the absolute base directories for a pattern.
func (e Env) bases(p Pattern) []string {
	switch p.Base {
	case "home":
		return []string{e.Home}
	case "appdata":
		if e.GOOS != "windows" {
			return nil
		}
		return []string{e.AppData}
	case "xdgconfig":
		if e.GOOS == "windows" {
			return nil
		}
		return []string{e.XDGConfig}
	case "xdgdata":
		if e.GOOS == "windows" {
			return nil
		}
		return []string{e.XDGData}
	case "vscode":
		var out []string
		for _, store := range vscodeStores {
			switch e.GOOS {
			case "darwin":
				out = append(out, filepath.Join(e.Home, "Library", "Application Support", store, "User", "globalStorage"))
			case "windows":
				out = append(out, filepath.Join(e.AppData, store, "User", "globalStorage"))
			default:
				out = append(out, filepath.Join(e.XDGConfig, store, "User", "globalStorage"))
			}
		}
		return out
	case "repo":
		return e.repoDirs()
	}
	return nil
}

// Display renders a pattern with a portable base for documentation.
func (p Pattern) Display() string {
	switch p.Base {
	case "home":
		return "~/" + p.Glob
	case "appdata":
		return "%APPDATA%/" + p.Glob
	case "xdgconfig":
		return "~/.config/" + p.Glob
	case "xdgdata":
		return "~/.local/share/" + p.Glob
	case "vscode":
		return "<vscode globalStorage>/" + p.Glob
	case "repo":
		return "<repo>/" + p.Glob
	}
	return p.Glob
}

// Discover finds every existing file for every tool.
func Discover(env Env, only []string) ([]Target, []Status) {
	env = env.Fill()
	want := map[string]bool{}
	for _, id := range only {
		want[id] = true
	}
	var targets []Target
	var statuses []Status
	seen := map[string]bool{}
	for _, tool := range Registry {
		if len(want) > 0 && !want[tool.ID] {
			continue
		}
		st := Status{Tool: tool.ID, Name: tool.Name}
		for _, hint := range tool.RootHint {
			if !hint.appliesTo(env.GOOS) {
				continue
			}
			for _, base := range env.bases(hint) {
				if base == "" {
					continue
				}
				if matches := expand(base, hint.Glob, 1); len(matches) > 0 {
					st.Found = true
					if st.RootPath == "" {
						st.RootPath = matches[0]
					}
				}
			}
		}
		for _, p := range tool.Patterns {
			if !p.appliesTo(env.GOOS) {
				continue
			}
			for _, base := range env.bases(p) {
				if base == "" {
					continue
				}
				for _, path := range expand(base, p.Glob, 0) {
					if seen[path] {
						continue
					}
					info, err := os.Stat(path)
					if err != nil || info.IsDir() {
						continue
					}
					seen[path] = true
					st.Found = true
					st.Files++
					st.Bytes += info.Size()
					targets = append(targets, Target{
						Tool: tool.ID, ToolName: tool.Name, Label: p.Label, Kind: p.Kind,
						Path: path, Size: info.Size(), ModTime: info.ModTime(), Credential: p.Credential,
					})
				}
			}
		}
		statuses = append(statuses, st)
	}
	sort.SliceStable(targets, func(i, j int) bool {
		if targets[i].Tool != targets[j].Tool {
			return false
		}
		return targets[i].Path < targets[j].Path
	})
	return targets, statuses
}

// repoDirs walks the configured repository roots to a depth limit and
// returns every directory, so repo-relative patterns can be applied.
func (e Env) repoDirs() []string {
	var dirs []string
	seen := map[string]bool{}
	for _, root := range e.RepoRoots {
		root = filepath.Clean(root)
		if st, err := os.Stat(root); err != nil || !st.IsDir() {
			continue
		}
		walkDirs(root, 0, e.RepoDepth, func(d string) {
			if !seen[d] {
				seen[d] = true
				dirs = append(dirs, d)
			}
		})
	}
	return dirs
}

// skipDirs are never descended into during repository discovery.
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "Library": true, ".cache": true, ".npm": true,
	".cargo": true, ".rustup": true, "go": true, ".venv": true, "venv": true, "target": true,
	"dist": true, "build": true, ".Trash": true, "Applications": true, "Music": true,
	"Movies": true, "Pictures": true, "Photos": true, ".pyenv": true, ".nvm": true,
	".gradle": true, ".m2": true, "Pods": true, "vendor": true, "__pycache__": true,
}

func walkDirs(dir string, depth, max int, fn func(string)) {
	fn(dir)
	if depth >= max {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, ent := range entries {
		if !ent.IsDir() || ent.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := ent.Name()
		if skipDirs[name] {
			continue
		}
		walkDirs(filepath.Join(dir, name), depth+1, max, fn)
	}
}

// expand resolves a glob (with ** support) under base. With allowDirs set to
// 1 directories are returned too, which is what root hints need.
func expand(base, glob string, allowDirs int) []string {
	segs := strings.Split(glob, "/")
	var out []string
	expandSegs(base, segs, allowDirs == 1, &out)
	return out
}

func hasMeta(s string) bool { return strings.ContainsAny(s, "*?[") }

func expandSegs(dir string, segs []string, allowDirs bool, out *[]string) {
	if len(segs) == 0 {
		if st, err := os.Lstat(dir); err == nil && (allowDirs || !st.IsDir()) {
			*out = append(*out, dir)
		}
		return
	}
	seg := segs[0]
	rest := segs[1:]
	switch {
	case seg == "**":
		// Zero directories.
		expandSegs(dir, rest, allowDirs, out)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, ent := range entries {
			if ent.IsDir() && ent.Type()&os.ModeSymlink == 0 {
				expandSegs(filepath.Join(dir, ent.Name()), segs, allowDirs, out)
			}
		}
	case seg == "..":
		expandSegs(filepath.Dir(dir), rest, allowDirs, out)
	case !hasMeta(seg):
		expandSegs(filepath.Join(dir, seg), rest, allowDirs, out)
	default:
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, ent := range entries {
			ok, err := filepath.Match(seg, ent.Name())
			if err != nil || !ok {
				continue
			}
			expandSegs(filepath.Join(dir, ent.Name()), rest, allowDirs, out)
		}
	}
}

// KindForPath guesses a Kind for an arbitrary user-supplied file.
func KindForPath(path string) Kind {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jsonl", ".ndjson":
		return KindJSONL
	case ".json":
		return KindJSON
	case ".db", ".sqlite", ".sqlite3", ".vscdb":
		return KindSQLite
	}
	return KindText
}

// Shorten replaces the home prefix of a path with ~ for display.
func Shorten(home, path string) string {
	if home != "" && strings.HasPrefix(path, home) {
		return "~" + path[len(home):]
	}
	return path
}
