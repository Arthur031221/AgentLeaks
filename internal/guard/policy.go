package guard

import (
	"bufio"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
)

// Secret path patterns. Basename globs use path.Match syntax and are checked
// against the file name only. Path files are checked as a suffix of the
// slash-separated path. Path dirs are checked as a directory component.
var (
	basenameGlobs = []string{
		".env", ".env.*", ".envrc",
		"*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.ppk",
		"id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
		".netrc", "_netrc", ".npmrc", ".pypirc", ".git-credentials", ".htpasswd",
		"terraform.tfvars", "*.tfstate", "*.tfstate.backup",
		"secrets.yaml", "secrets.yml", "secrets.json", "credentials.json",
		"service-account*.json", "*service_account*.json",
		"*.secret", "*.secrets",
		".claude.json", ".mcp.json",
	}
	// Files that look like .env but are meant to be committed.
	envExcludes = []string{".env.example", ".env.sample", ".env.template", ".env.dist"}
	pathFiles   = []string{
		".docker/config.json", ".aws/credentials", ".aws/config", ".kube/config",
		".claude/.credentials.json",
		".codex/auth.json", ".codex/config.toml",
		".cursor/mcp.json",
		".gemini/oauth_creds.json", ".gemini/.env", ".gemini/settings.json",
		".copilot/config.json", ".copilot/mcp-config.json",
		"Library/Application Support/Claude/claude_desktop_config.json",
		".config/devin/mcp_config.json", ".codeium/windsurf/mcp_config.json",
		".continue/config.yaml", ".continue/config.json",
		".local/share/opencode/auth.json",
	}
	pathDirs = []string{".config/gcloud/", ".ssh/", ".gnupg/"}
)

// Policy decides whether a path or a shell command touches secret material.
type Policy struct {
	home  string
	extra []string
}

// DefaultPolicy returns the built-in policy plus any extra globs listed in
// <home>/.agentleaks/guard-paths.txt, one per line, # for comments.
func DefaultPolicy(home string) *Policy {
	p := &Policy{home: home}
	if home == "" {
		return p
	}
	f, err := os.Open(filepath.Join(home, ".agentleaks", "guard-paths.txt"))
	if err != nil {
		return p
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := pathpkg.Match(line, ""); err != nil {
			continue
		}
		p.extra = append(p.extra, line)
	}
	return p
}

// normalize expands ~ and $HOME and converts the path to slash form.
func (p *Policy) normalize(path string) string {
	path = strings.TrimSpace(path)
	switch {
	case path == "~":
		path = p.home
	case strings.HasPrefix(path, "~/"):
		path = p.home + path[1:]
	case strings.HasPrefix(path, "$HOME/") || path == "$HOME":
		path = p.home + path[5:]
	case strings.HasPrefix(path, "${HOME}/") || path == "${HOME}":
		path = p.home + path[7:]
	}
	path = filepath.ToSlash(path)
	if path == "" {
		return path
	}
	return pathpkg.Clean(path)
}

// PathIsSecret reports whether path matches a secret pattern and which one.
func (p *Policy) PathIsSecret(path string) (bool, string) {
	norm := p.normalize(path)
	if norm == "" || norm == "." || norm == "/" {
		return false, ""
	}
	base := pathpkg.Base(norm)
	for _, ex := range envExcludes {
		if base == ex {
			return false, ""
		}
	}
	for _, g := range basenameGlobs {
		if ok, _ := pathpkg.Match(g, base); ok {
			return true, g
		}
	}
	withSlash := "/" + strings.TrimPrefix(norm, "/")
	for _, f := range pathFiles {
		if strings.HasSuffix(withSlash, "/"+f) {
			return true, f
		}
	}
	for _, d := range pathDirs {
		if strings.Contains(withSlash+"/", "/"+d) {
			return true, d
		}
	}
	for _, g := range p.extra {
		if matchExtra(g, norm, base) {
			return true, "guard-paths.txt: " + g
		}
	}
	return false, ""
}

// matchExtra applies a user glob to the basename, or when the glob contains a
// slash, to the full path and every trailing sub-path of it.
func matchExtra(glob, norm, base string) bool {
	if !strings.Contains(glob, "/") {
		ok, _ := pathpkg.Match(glob, base)
		return ok
	}
	parts := strings.Split(strings.TrimPrefix(norm, "/"), "/")
	for i := range parts {
		if ok, _ := pathpkg.Match(glob, strings.Join(parts[i:], "/")); ok {
			return true
		}
	}
	ok, _ := pathpkg.Match(glob, norm)
	return ok
}

var (
	secretVarRe = regexp.MustCompile(`(?i)(key|token|secret|password|passwd|credential)`)
	varRefRe    = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	assignRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	prefixCmds  = map[string]bool{
		"sudo": true, "command": true, "exec": true, "builtin": true,
		"time": true, "nohup": true, "nice": true,
	}
)

// CommandIsSecret reports whether a shell command reads secret material.
// It checks every path-like token against the policy and denies a few forms
// that dump the environment.
func (p *Policy) CommandIsSecret(cmd string) (bool, string) {
	for _, seg := range splitCommand(cmd) {
		words := stripPrefixes(seg)
		if len(words) > 0 {
			name := pathpkg.Base(words[0])
			args := words[1:]
			switch name {
			case "env", "printenv", "export", "set", "declare":
				if len(args) == 0 {
					return true, name + " prints the whole environment"
				}
			}
			if name == "printenv" {
				for _, a := range args {
					if secretVarRe.MatchString(a) {
						return true, "printenv " + a
					}
				}
			}
			if name == "echo" || name == "printf" {
				for _, a := range args {
					for _, m := range varRefRe.FindAllStringSubmatch(a, -1) {
						if secretVarRe.MatchString(m[1]) {
							return true, "prints $" + m[1]
						}
					}
				}
			}
		}
		for _, w := range seg {
			for _, cand := range tokenCandidates(w) {
				if ok, why := p.PathIsSecret(cand); ok {
					return true, cand + " matches " + why
				}
			}
		}
	}
	return false, ""
}

func stripPrefixes(words []string) []string {
	for len(words) > 0 {
		w := words[0]
		if prefixCmds[pathpkg.Base(w)] || assignRe.MatchString(w) {
			words = words[1:]
			continue
		}
		break
	}
	return words
}

// tokenCandidates strips shell decoration from a word and returns the
// strings worth checking as paths.
func tokenCandidates(w string) []string {
	for {
		before := w
		w = strings.TrimPrefix(w, "$(")
		w = strings.TrimLeft(w, "`({<>&")
		w = strings.TrimRight(w, "`)};,&")
		if w == before {
			break
		}
	}
	if w == "" {
		return nil
	}
	var out []string
	if idx := strings.Index(w, "="); idx > 0 {
		out = append(out, w[idx+1:])
	}
	if !strings.HasPrefix(w, "-") {
		out = append(out, w)
	}
	return out
}

// splitCommand tokenizes a shell command into segments of words. Quotes are
// honored, control operators start a new segment, and redirection operators
// are dropped so their targets become plain words.
func splitCommand(cmd string) [][]string {
	var segs [][]string
	var cur []string
	var word strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			cur = append(cur, word.String())
			word.Reset()
			inWord = false
		}
	}
	endSeg := func() {
		flush()
		if len(cur) > 0 {
			segs = append(segs, cur)
			cur = nil
		}
	}
	rs := []rune(cmd)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\'':
			inWord = true
			i++
			for i < len(rs) && rs[i] != '\'' {
				word.WriteRune(rs[i])
				i++
			}
		case c == '"':
			inWord = true
			i++
			for i < len(rs) && rs[i] != '"' {
				if rs[i] == '\\' && i+1 < len(rs) {
					i++
				}
				word.WriteRune(rs[i])
				i++
			}
		case c == '\\' && i+1 < len(rs):
			inWord = true
			i++
			word.WriteRune(rs[i])
		case c == ' ' || c == '\t' || c == '\r':
			flush()
		case c == '\n' || c == ';' || c == '|' || c == '&':
			endSeg()
			for i+1 < len(rs) && (rs[i+1] == '|' || rs[i+1] == '&') {
				i++
			}
		case c == '<' || c == '>':
			flush()
			for i+1 < len(rs) && (rs[i+1] == '<' || rs[i+1] == '>' || rs[i+1] == '&' || (rs[i+1] >= '0' && rs[i+1] <= '9')) {
				i++
			}
		default:
			inWord = true
			word.WriteRune(c)
		}
	}
	endSeg()
	return segs
}
