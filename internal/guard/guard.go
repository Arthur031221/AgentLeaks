// Package guard installs hooks into AI coding tools and runs them. The hooks
// deny tool calls that read secret files and, where the tool supports it,
// scrub secrets out of tool output before the model sees it.
package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Tool identifiers.
const (
	ToolClaudeCode = "claude-code"
	ToolCodex      = "codex"
	ToolCursor     = "cursor"
	ToolGemini     = "gemini"
	ToolCopilot    = "copilot"
)

// hookMarker identifies hook entries written by this package.
const hookMarker = "agentleaks hook"

// Tools lists the supported tools in display order.
func Tools() []string {
	return []string{ToolClaudeCode, ToolCodex, ToolCursor, ToolGemini, ToolCopilot}
}

// Coverage describes what the hook can do for one tool.
type Coverage struct {
	Tool        string
	ConfigPath  string
	DenyRead    bool
	DenyShell   bool
	ScrubOutput bool
	Events      []string
	Notes       string
}

// InstallOptions controls Install and Uninstall.
type InstallOptions struct {
	Home   string
	Binary string
	Tools  []string
	DryRun bool
	Force  bool
}

// InstallResult reports what happened for one tool.
type InstallResult struct {
	Tool   string
	Path   string
	Action string
	Err    error
}

type hookSpec struct {
	tool     string
	dir      string
	file     string
	owned    bool
	version  bool
	entries  func(bin string) map[string][]any
	coverage Coverage
}

func cmdEntry(bin, tool, event string, matcher string, timeout int, name string) map[string]any {
	hook := map[string]any{
		"type":    "command",
		"command": bin + " hook " + tool + " " + event,
		"timeout": timeout,
	}
	if name != "" {
		hook["name"] = name
	}
	return map[string]any{
		"matcher": matcher,
		"hooks":   []any{hook},
	}
}

var specs = []hookSpec{
	{
		tool: ToolClaudeCode, dir: ".claude", file: filepath.Join(".claude", "settings.json"),
		entries: func(bin string) map[string][]any {
			return map[string][]any{
				"PreToolUse":  {cmdEntry(bin, ToolClaudeCode, "PreToolUse", "Read|Bash|Grep|Glob|Edit|Write|MultiEdit|NotebookEdit", 10, "")},
				"PostToolUse": {cmdEntry(bin, ToolClaudeCode, "PostToolUse", "Read|Bash|Grep", 10, "")},
			}
		},
		coverage: Coverage{
			Tool: ToolClaudeCode, ConfigPath: "~/.claude/settings.json",
			DenyRead: true, DenyShell: true, ScrubOutput: true,
			Events: []string{"PreToolUse", "PostToolUse"},
			Notes:  "Covers Read, Bash, Grep, Glob, Edit and Write. MCP tools that read files are not matched.",
		},
	},
	{
		tool: ToolCodex, dir: ".codex", file: filepath.Join(".codex", "hooks.json"),
		entries: func(bin string) map[string][]any {
			return map[string][]any{
				"PreToolUse": {cmdEntry(bin, ToolCodex, "PreToolUse", "Bash", 10, "")},
			}
		},
		coverage: Coverage{
			Tool: ToolCodex, ConfigPath: "~/.codex/hooks.json",
			DenyRead: false, DenyShell: true, ScrubOutput: false,
			Events: []string{"PreToolUse"},
			Notes:  "Codex reads files through shell commands, so the Bash hook covers reads. apply_patch and MCP tools are not covered.",
		},
	},
	{
		tool: ToolCursor, dir: ".cursor", file: filepath.Join(".cursor", "hooks.json"), version: true,
		entries: func(bin string) map[string][]any {
			return map[string][]any{
				"beforeShellExecution": {map[string]any{"command": bin + " hook cursor beforeShellExecution"}},
				"beforeReadFile":       {map[string]any{"command": bin + " hook cursor beforeReadFile"}},
			}
		},
		coverage: Coverage{
			Tool: ToolCursor, ConfigPath: "~/.cursor/hooks.json",
			DenyRead: true, DenyShell: true, ScrubOutput: false,
			Events: []string{"beforeShellExecution", "beforeReadFile"},
			Notes:  "beforeReadFile also covers attached files. MCP tool calls are not inspected.",
		},
	},
	{
		tool: ToolGemini, dir: ".gemini", file: filepath.Join(".gemini", "settings.json"),
		entries: func(bin string) map[string][]any {
			return map[string][]any{
				"BeforeTool": {cmdEntry(bin, ToolGemini, "BeforeTool", "read_file|run_shell_command|read_many_files|glob|grep_search", 10000, "agentleaks")},
			}
		},
		coverage: Coverage{
			Tool: ToolGemini, ConfigPath: "~/.gemini/settings.json",
			DenyRead: true, DenyShell: true, ScrubOutput: false,
			Events: []string{"BeforeTool"},
			Notes:  "Covers read_file, run_shell_command, read_many_files, glob and grep_search. Output scrubbing through AfterTool is not implemented.",
		},
	},
	{
		tool: ToolCopilot, dir: ".copilot", file: filepath.Join(".copilot", "hooks", "agentleaks.json"), owned: true,
		entries: func(bin string) map[string][]any {
			return map[string][]any{
				"preToolUse": {map[string]any{
					"type":       "command",
					"bash":       bin + " hook copilot preToolUse",
					"timeoutSec": 10,
				}},
			}
		},
		coverage: Coverage{
			Tool: ToolCopilot, ConfigPath: "~/.copilot/hooks/agentleaks.json",
			DenyRead: true, DenyShell: true, ScrubOutput: false,
			Events: []string{"preToolUse"},
			Notes:  "Copilot CLI does not document tool names, so paths and commands are taken from toolArgs by key name. Hook timeouts fail open.",
		},
	},
}

func specFor(tool string) (hookSpec, bool) {
	for _, s := range specs {
		if s.tool == tool {
			return s, true
		}
	}
	return hookSpec{}, false
}

// CoverageTable returns the honest coverage description for every tool.
func CoverageTable() []Coverage {
	out := make([]Coverage, 0, len(specs))
	for _, s := range specs {
		c := s.coverage
		c.Events = append([]string(nil), c.Events...)
		out = append(out, c)
	}
	return out
}

func resolve(opts InstallOptions) (home, bin string, err error) {
	home = opts.Home
	if home == "" {
		home, err = os.UserHomeDir()
		if err != nil {
			return "", "", err
		}
	}
	bin = opts.Binary
	if bin == "" {
		bin, err = os.Executable()
		if err != nil {
			return "", "", err
		}
	}
	if strings.ContainsAny(bin, " \t") {
		bin = `"` + bin + `"`
	}
	return home, bin, nil
}

func selectedTools(opts InstallOptions) []string {
	if len(opts.Tools) == 0 {
		return Tools()
	}
	return opts.Tools
}

// Install writes hook entries for the selected tools.
func Install(opts InstallOptions) []InstallResult {
	home, bin, err := resolve(opts)
	if err != nil {
		return []InstallResult{{Action: "error", Err: err}}
	}
	var results []InstallResult
	for _, tool := range selectedTools(opts) {
		spec, ok := specFor(tool)
		if !ok {
			results = append(results, InstallResult{Tool: tool, Action: "error", Err: fmt.Errorf("unknown tool %q", tool)})
			continue
		}
		path := filepath.Join(home, spec.file)
		res := InstallResult{Tool: tool, Path: path}
		if !opts.Force && !dirExists(filepath.Join(home, spec.dir)) {
			res.Action = "skipped-not-found"
			results = append(results, res)
			continue
		}
		if spec.owned {
			res.Action, res.Err = installOwned(spec, path, bin, opts.DryRun)
		} else {
			res.Action, res.Err = installMerge(spec, path, bin, opts.DryRun)
		}
		if res.Err != nil {
			res.Action = "error"
		}
		results = append(results, res)
	}
	return results
}

// Uninstall removes hook entries written by Install.
func Uninstall(opts InstallOptions) []InstallResult {
	home, _, err := resolve(opts)
	if err != nil {
		return []InstallResult{{Action: "error", Err: err}}
	}
	var results []InstallResult
	for _, tool := range selectedTools(opts) {
		spec, ok := specFor(tool)
		if !ok {
			results = append(results, InstallResult{Tool: tool, Action: "error", Err: fmt.Errorf("unknown tool %q", tool)})
			continue
		}
		path := filepath.Join(home, spec.file)
		res := InstallResult{Tool: tool, Path: path}
		if spec.owned {
			res.Action, res.Err = uninstallOwned(path, opts.DryRun)
		} else {
			res.Action, res.Err = uninstallMerge(path, opts.DryRun)
		}
		if res.Err != nil {
			res.Action = "error"
		}
		results = append(results, res)
	}
	return results
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func readJSONFile(path string) (map[string]any, os.FileMode, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, 0o600, nil
	}
	if err != nil {
		return nil, 0, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	m := map[string]any{}
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, 0, fmt.Errorf("%s is not valid JSON, not touching it: %w", path, err)
		}
	}
	return m, st.Mode().Perm(), nil
}

func writeJSONFile(path string, v any, mode os.FileMode) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), mode)
}

// isOurs reports whether a hook entry references the agentleaks hook command.
func isOurs(v any) bool {
	switch t := v.(type) {
	case string:
		return strings.Contains(t, hookMarker)
	case []any:
		for _, item := range t {
			if isOurs(item) {
				return true
			}
		}
	case map[string]any:
		for k, item := range t {
			if k == "command" || k == "bash" || k == "powershell" || k == "hooks" {
				if isOurs(item) {
					return true
				}
			}
		}
	}
	return false
}

func installMerge(spec hookSpec, path, bin string, dryRun bool) (string, error) {
	data, mode, err := readJSONFile(path)
	if err != nil {
		return "", err
	}
	hooks, ok := data["hooks"].(map[string]any)
	if !ok {
		if _, present := data["hooks"]; present {
			return "", fmt.Errorf("%s: hooks is not an object", path)
		}
		hooks = map[string]any{}
	}
	added := false
	for event, entries := range spec.entries(bin) {
		arr, _ := hooks[event].([]any)
		have := false
		for _, e := range arr {
			if isOurs(e) {
				have = true
				break
			}
		}
		if have {
			continue
		}
		arr = append(arr, entries...)
		hooks[event] = arr
		added = true
	}
	if !added {
		return "already-installed", nil
	}
	if dryRun {
		return "would-install", nil
	}
	data["hooks"] = hooks
	if spec.version {
		if _, present := data["version"]; !present {
			data["version"] = 1
		}
	}
	if err := writeJSONFile(path, data, mode); err != nil {
		return "", err
	}
	return "installed", nil
}

func uninstallMerge(path string, dryRun bool) (string, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return "not-installed", nil
	}
	data, mode, err := readJSONFile(path)
	if err != nil {
		return "", err
	}
	hooks, ok := data["hooks"].(map[string]any)
	if !ok {
		return "not-installed", nil
	}
	removed := false
	for event, v := range hooks {
		arr, ok := v.([]any)
		if !ok {
			continue
		}
		kept := arr[:0:0]
		for _, e := range arr {
			if isOurs(e) {
				removed = true
				continue
			}
			kept = append(kept, e)
		}
		if len(kept) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = kept
		}
	}
	if !removed {
		return "not-installed", nil
	}
	if dryRun {
		return "would-remove", nil
	}
	if len(hooks) == 0 {
		delete(data, "hooks")
	} else {
		data["hooks"] = hooks
	}
	if err := writeJSONFile(path, data, mode); err != nil {
		return "", err
	}
	return "removed", nil
}

func installOwned(spec hookSpec, path, bin string, dryRun bool) (string, error) {
	if existing, err := os.ReadFile(path); err == nil && strings.Contains(string(existing), hookMarker) {
		return "already-installed", nil
	}
	if dryRun {
		return "would-install", nil
	}
	content := map[string]any{"version": 1, "hooks": spec.entries(bin)}
	if err := writeJSONFile(path, content, 0o600); err != nil {
		return "", err
	}
	return "installed", nil
}

func uninstallOwned(path string, dryRun bool) (string, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return "not-installed", nil
	}
	if dryRun {
		return "would-remove", nil
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return "removed", nil
}
