package guard

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/Arthur031221/agentleaks/internal/rules"
)

// maxPayload bounds the hook payload read from stdin.
const maxPayload = 32 << 20

var (
	pathKeys = map[string]bool{
		"file_path": true, "filePath": true, "path": true, "absolute_path": true,
		"notebook_path": true, "paths": true, "files": true, "dir_path": true,
		"directory": true,
	}
	cmdKeys = map[string]bool{"command": true, "cmd": true, "script": true}
)

// extract walks a tool input and returns candidate paths and commands.
func extract(input map[string]any) (paths, cmds []string) {
	var walk func(key string, v any)
	walk = func(key string, v any) {
		switch t := v.(type) {
		case string:
			if pathKeys[key] {
				paths = append(paths, t)
			} else if cmdKeys[key] {
				cmds = append(cmds, t)
			}
		case []any:
			if cmdKeys[key] {
				var parts []string
				for _, item := range t {
					if s, ok := item.(string); ok {
						parts = append(parts, s)
					}
				}
				if len(parts) > 0 {
					cmds = append(cmds, strings.Join(parts, " "))
				}
				return
			}
			for _, item := range t {
				walk(key, item)
			}
		case map[string]any:
			for k, vv := range t {
				walk(k, vv)
			}
		}
	}
	for k, v := range input {
		walk(k, v)
	}
	return paths, cmds
}

// decide applies the policy to candidate paths and commands.
func decide(p *Policy, paths, cmds []string) (bool, string) {
	for _, path := range paths {
		if ok, why := p.PathIsSecret(path); ok {
			return true, fmt.Sprintf("agentleaks blocked access to %s (matches %s). Ask the user for the value instead of reading the file.", path, why)
		}
	}
	for _, c := range cmds {
		if ok, why := p.CommandIsSecret(c); ok {
			return true, fmt.Sprintf("agentleaks blocked this command because it reads secret material (%s). Ask the user for the value instead.", why)
		}
	}
	return false, ""
}

func policyHome() string {
	if h := os.Getenv("AGENTLEAKS_HOME"); h != "" {
		return h
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

func readPayload(r io.Reader) (map[string]any, bool) {
	data, err := io.ReadAll(io.LimitReader(r, maxPayload))
	if err != nil || len(data) == 0 {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

func inputMap(payload map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		if m, ok := payload[k].(map[string]any); ok {
			return m
		}
	}
	return nil
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// Run executes one hook invocation for the given tool and event. It reads
// the JSON payload from stdin, answers in the tool's protocol, and returns
// the process exit code. Malformed input fails open with exit 0 and no output.
func Run(tool, event string, stdin io.Reader, stdout, stderr io.Writer) int {
	defer func() { _ = recover() }()
	payload, ok := readPayload(stdin)
	if !ok {
		return 0
	}
	policy := DefaultPolicy(policyHome())
	switch tool {
	case ToolClaudeCode:
		switch event {
		case "PreToolUse":
			return runExitTwo(policy, payload, stderr)
		case "PostToolUse":
			return runClaudePostToolUse(payload, stdout)
		}
	case ToolCodex:
		if event == "PreToolUse" {
			return runExitTwo(policy, payload, stderr)
		}
	case ToolCursor:
		switch event {
		case "beforeShellExecution", "beforeReadFile":
			return runCursor(policy, payload, stdout)
		}
	case ToolGemini:
		if event == "BeforeTool" {
			return runGemini(policy, payload, stdout)
		}
	case ToolCopilot:
		if event == "preToolUse" {
			return runCopilot(policy, payload, stdout)
		}
	}
	return 0
}

// runExitTwo implements the Claude Code and Codex protocol: exit 2 with the
// reason on stderr blocks the tool call.
func runExitTwo(p *Policy, payload map[string]any, stderr io.Writer) int {
	input := inputMap(payload, "tool_input")
	if input == nil {
		return 0
	}
	paths, cmds := extract(input)
	if deny, reason := decide(p, paths, cmds); deny {
		fmt.Fprintln(stderr, reason)
		return 2
	}
	return 0
}

func runCursor(p *Policy, payload map[string]any, stdout io.Writer) int {
	paths, cmds := extract(payload)
	if deny, reason := decide(p, paths, cmds); deny {
		writeJSON(stdout, map[string]any{
			"permission":    "deny",
			"user_message":  reason,
			"agent_message": reason,
		})
		return 0
	}
	writeJSON(stdout, map[string]any{"permission": "allow"})
	return 0
}

func runGemini(p *Policy, payload map[string]any, stdout io.Writer) int {
	input := inputMap(payload, "tool_input")
	if input == nil {
		return 0
	}
	paths, cmds := extract(input)
	if deny, reason := decide(p, paths, cmds); deny {
		writeJSON(stdout, map[string]any{"decision": "deny", "reason": reason})
	}
	return 0
}

func runCopilot(p *Policy, payload map[string]any, stdout io.Writer) int {
	input := inputMap(payload, "toolArgs", "tool_input")
	if input == nil {
		return 0
	}
	paths, cmds := extract(input)
	if deny, reason := decide(p, paths, cmds); deny {
		writeJSON(stdout, map[string]any{
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		})
	}
	return 0
}

var (
	ruleSetOnce sync.Once
	ruleSet     *rules.Set
)

func loadRules() *rules.Set {
	ruleSetOnce.Do(func() {
		s, err := rules.Load()
		if err == nil {
			ruleSet = s
		}
	})
	return ruleSet
}

// runClaudePostToolUse scrubs secrets from a tool result before the model
// sees it, using the updatedToolOutput field.
func runClaudePostToolUse(payload map[string]any, stdout io.Writer) int {
	set := loadRules()
	if set == nil {
		return 0
	}
	var output any
	var found bool
	for _, k := range []string{"tool_output", "tool_response"} {
		if v, ok := payload[k]; ok && v != nil {
			output, found = v, true
			break
		}
	}
	if !found {
		return 0
	}
	redacted, changed := redactValue(set, output)
	if !changed {
		return 0
	}
	writeJSON(stdout, map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "PostToolUse",
			"updatedToolOutput": redacted,
		},
	})
	return 0
}

// redactValue replaces secrets inside every string of a JSON value.
func redactValue(set *rules.Set, v any) (any, bool) {
	switch t := v.(type) {
	case string:
		return redactText(set, t)
	case []any:
		changed := false
		out := make([]any, len(t))
		for i, item := range t {
			nv, c := redactValue(set, item)
			out[i] = nv
			changed = changed || c
		}
		return out, changed
	case map[string]any:
		changed := false
		out := make(map[string]any, len(t))
		for k, item := range t {
			nv, c := redactValue(set, item)
			out[k] = nv
			changed = changed || c
		}
		return out, changed
	}
	return v, false
}

// redactText replaces every secret in s with the rule's redaction marker.
// Block rules (private keys) are extended to their closing marker.
func redactText(set *rules.Set, s string) (string, bool) {
	text := []byte(s)
	matches := set.Scan(text)
	if len(matches) == 0 {
		return s, false
	}
	type span struct {
		start, end int
		id         string
	}
	spans := make([]span, 0, len(matches))
	for _, m := range matches {
		end := m.End
		if m.Rule.IsBlock() {
			if loc := m.Rule.BlockEnd.FindIndex(text[m.End:]); loc != nil {
				end = m.End + loc[1]
			}
		}
		spans = append(spans, span{m.Start, end, m.Rule.ID})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })
	var b strings.Builder
	last := len(text)
	pieces := make([]string, 0, len(spans)*2+1)
	for _, sp := range spans {
		if sp.end > last {
			sp.end = last
		}
		if sp.start >= sp.end {
			continue
		}
		pieces = append(pieces, string(text[sp.end:last]), rules.Redaction(sp.id))
		last = sp.start
	}
	pieces = append(pieces, string(text[:last]))
	for i := len(pieces) - 1; i >= 0; i-- {
		b.WriteString(pieces[i])
	}
	return b.String(), true
}
