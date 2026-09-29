package guard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathIsSecret(t *testing.T) {
	p := DefaultPolicy("/home/tester")
	cases := []struct {
		path string
		want bool
	}{
		{".env", true},
		{"/srv/app/.env", true},
		{".env.local", true},
		{".env.production", true},
		{".env.example", false},
		{".env.sample", false},
		{".env.template", false},
		{".env.dist", false},
		{"~/.ssh/id_rsa", true},
		{"/home/tester/.ssh/id_rsa", true},
		{"/home/tester/.ssh/known_hosts", true},
		{"$HOME/.aws/credentials", true},
		{"~/.aws/credentials", true},
		{".aws/credentials", true},
		{"/etc/app/service-account-prod.json", true},
		{"/tmp/my_service_account_key.json", true},
		{"server.pem", true},
		{"/x/y/private.key", true},
		{"terraform.tfstate", true},
		{"/home/tester/.claude.json", true},
		{"/home/tester/.codex/auth.json", true},
		{"/home/tester/.cursor/mcp.json", true},
		{"/home/tester/.gemini/oauth_creds.json", true},
		{"/home/tester/Library/Application Support/Claude/claude_desktop_config.json", true},
		{"/home/tester/.config/gcloud/application_default_credentials.json", true},
		{"README.md", false},
		{"main.go", false},
		{"/home/tester/project/src/main.go", false},
		{"package.json", false},
		{"settings.json", false},
		{"", false},
		{"/", false},
		{"config.yaml", false},
	}
	for _, c := range cases {
		got, why := p.PathIsSecret(c.path)
		if got != c.want {
			t.Errorf("PathIsSecret(%q) = %v (%s), want %v", c.path, got, why, c.want)
		}
		if got && why == "" {
			t.Errorf("PathIsSecret(%q) gave no reason", c.path)
		}
	}
}

func TestExtraGlobs(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".agentleaks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := "# comment\n\n*.vault\nconfig/prod/*.yaml\n"
	if err := os.WriteFile(filepath.Join(dir, "guard-paths.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy(home)
	if ok, _ := p.PathIsSecret("/srv/keys.vault"); !ok {
		t.Error("expected *.vault to match")
	}
	if ok, _ := p.PathIsSecret("/srv/app/config/prod/db.yaml"); !ok {
		t.Error("expected config/prod/*.yaml to match nested path")
	}
	if ok, _ := p.PathIsSecret("/srv/app/config/dev/db.yaml"); ok {
		t.Error("did not expect config/dev to match")
	}
}

func TestCommandIsSecret(t *testing.T) {
	p := DefaultPolicy("/home/tester")
	deny := []string{
		"cat .env",
		"cat ~/.aws/credentials",
		"grep KEY .env",
		"source .env",
		". .env",
		"export $(cat .env)",
		"set -a; . .env",
		"printenv",
		"env",
		"env | grep -i key",
		"printenv OPENAI_API_KEY",
		"echo $OPENAI_API_KEY",
		"echo ${ANTHROPIC_API_KEY}",
		`echo "token: $GITHUB_TOKEN"`,
		"cat \"$HOME/.ssh/id_ed25519\"",
		"cat '.env.local'",
		"head -c 100 .env 2>/dev/null",
		"cat .env>out.txt",
		"sudo cat /etc/app/.env",
		"cat config/../.env",
		"cp .env.example .env",
		"cat ~/.codex/auth.json",
		"less ~/.claude.json",
		"docker run --env-file=.env img",
	}
	allow := []string{
		"ls -la",
		"git status",
		"go test ./...",
		"cat README.md",
		"npm test",
		"cat .env.example",
		"echo $PATH",
		"printenv PATH",
		"env FOO=bar ./run.sh",
		"grep -rn TODO src/",
		"python3 -m pytest -q",
		"make build",
		"",
		"   ",
	}
	for _, c := range deny {
		if ok, _ := p.CommandIsSecret(c); !ok {
			t.Errorf("expected deny for %q", c)
		}
	}
	for _, c := range allow {
		if ok, why := p.CommandIsSecret(c); ok {
			t.Errorf("expected allow for %q, denied because %s", c, why)
		}
	}
}

func TestSplitCommand(t *testing.T) {
	segs := splitCommand(`cat "a b.txt" | grep x && echo 'done' > out.txt`)
	want := [][]string{{"cat", "a b.txt"}, {"grep", "x"}, {"echo", "done", "out.txt"}}
	if len(segs) != len(want) {
		t.Fatalf("segments = %v, want %v", segs, want)
	}
	for i := range want {
		if len(segs[i]) != len(want[i]) {
			t.Fatalf("segment %d = %v, want %v", i, segs[i], want[i])
		}
		for j := range want[i] {
			if segs[i][j] != want[i][j] {
				t.Errorf("segment %d word %d = %q, want %q", i, j, segs[i][j], want[i][j])
			}
		}
	}
}
