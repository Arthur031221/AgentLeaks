package scan

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arthur031221/agentleaks/internal/rules"
	"github.com/Arthur031221/agentleaks/internal/sources"
	_ "modernc.org/sqlite"
)

// Fixtures are assembled from fragments at run time so that no complete
// secret pattern ever appears in the repository.

func fakeGitHubPAT() string { return "ghp_" + strings.Repeat("ab", 18) }

func fakeAnthropicKey() string { return "sk-ant-" + "api03-" + strings.Repeat("Z7", 25) }

func pemHeader() string { return "-----BEGIN " + "RSA PRIVATE KEY-----" }

func pemFooter() string { return "-----END " + "RSA PRIVATE KEY-----" }

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func target(t *testing.T, path string, kind sources.Kind) sources.Target {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return sources.Target{Tool: "test", ToolName: "Test", Label: "fixture", Kind: kind, Path: path, Size: info.Size(), ModTime: info.ModTime()}
}

type lineRec struct {
	no, off, overlap int
	text             []byte
}

func collect(t *testing.T, input string, maxLine int) []lineRec {
	t.Helper()
	var out []lineRec
	err := ReadLines(strings.NewReader(input), maxLine, func(no, off, ov int, line []byte) error {
		out = append(out, lineRec{no, off, ov, append([]byte(nil), line...)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReadLinesBasic(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"normal", "a\nb\nc\n", []string{"a", "b", "c"}},
		{"crlf", "a\r\nb\r\n", []string{"a", "b"}},
		{"no trailing newline", "a\nb", []string{"a", "b"}},
		{"empty file", "", nil},
		{"empty line in middle", "a\n\nb\n", []string{"a", "", "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := collect(t, c.input, 4096)
			if len(got) != len(c.want) {
				t.Fatalf("got %d lines, want %d", len(got), len(c.want))
			}
			for i, w := range c.want {
				if string(got[i].text) != w {
					t.Errorf("line %d = %q, want %q", i+1, got[i].text, w)
				}
				if got[i].no != i+1 || got[i].off != 0 {
					t.Errorf("line %d has no=%d off=%d", i+1, got[i].no, got[i].off)
				}
			}
		})
	}
}

func TestReadLinesLongLineChunks(t *testing.T) {
	// Chunking only starts once the buffered reader fills, so the line has
	// to be longer than readBuf. Three times readBuf makes several chunks.
	long := bytes.Repeat([]byte("x"), 3*readBuf)
	input := string(long) + "\nsecond\n"
	got := collect(t, input, 4096)
	if len(got) < 3 {
		t.Fatalf("expected several chunks plus a second line, got %d callbacks", len(got))
	}
	last := got[len(got)-1]
	if last.no != 2 || last.off != 0 || string(last.text) != "second" {
		t.Fatalf("last callback = %+v, want line 2 offset 0 %q", last.no, "second")
	}
	chunks := got[:len(got)-1]
	prevOff := -1
	for i, c := range chunks {
		if c.no != 1 {
			t.Errorf("chunk %d has line number %d, want 1", i, c.no)
		}
		if c.off <= prevOff {
			t.Errorf("chunk %d offset %d is not increasing (previous %d)", i, c.off, prevOff)
		}
		prevOff = c.off
		if c.off+len(c.text) > len(long) {
			t.Fatalf("chunk %d runs past the line", i)
		}
		if !bytes.Equal(c.text, long[c.off:c.off+len(c.text)]) {
			t.Errorf("chunk %d content does not match the line at its offset", i)
		}
	}
	end := chunks[len(chunks)-1]
	if end.off+len(end.text) != len(long) {
		t.Errorf("chunks end at %d, want %d", end.off+len(end.text), len(long))
	}
}

func TestReaderFindsSecretAfterFirstChunk(t *testing.T) {
	pat := fakeGitHubPAT()
	// The rule needs a word boundary, so the token is surrounded by spaces.
	pos := readBuf + 1000
	var b bytes.Buffer
	b.WriteString(strings.Repeat("y", pos-1))
	b.WriteString(" " + pat + " ")
	b.WriteString(strings.Repeat("y", 500))
	b.WriteString("\n")
	opts := Options{Rules: rules.MustLoad(), MaxLine: 4096}
	type hit struct{ line, col int }
	var hits []hit
	err := Reader(context.Background(), opts, &b, func(line, col int, m rules.Match) {
		if m.Secret == pat {
			hits = append(hits, hit{line, col})
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 {
		t.Fatal("secret after the first chunk was not found")
	}
	for _, h := range hits {
		if h.line != 1 || h.col != pos+1 {
			t.Errorf("hit at line %d col %d, want line 1 col %d", h.line, h.col, pos+1)
		}
	}
}

func TestLineScannerBlockState(t *testing.T) {
	ls := NewLineScanner(rules.MustLoad())
	r1 := ls.Next([]byte(pemHeader()))
	if len(r1.Matches) != 1 || r1.Matches[0].Rule.ID != "private-key" || r1.BlockRule != nil {
		t.Fatalf("header line: %+v", r1)
	}
	for i, body := range []string{"MIIBogIBAAJBAK", "abcdefghijklmnop"} {
		r := ls.Next([]byte(body))
		if r.BlockRule == nil || r.BlockEnds || len(r.Matches) != 0 {
			t.Fatalf("body line %d: BlockRule=%v BlockEnds=%v matches=%d", i, r.BlockRule != nil, r.BlockEnds, len(r.Matches))
		}
	}
	r4 := ls.Next([]byte(pemFooter()))
	if r4.BlockRule == nil || !r4.BlockEnds {
		t.Fatalf("footer line: BlockRule=%v BlockEnds=%v", r4.BlockRule != nil, r4.BlockEnds)
	}
	r5 := ls.Next([]byte("after " + fakeGitHubPAT()))
	if r5.BlockRule != nil || len(r5.Matches) != 1 || r5.Matches[0].Rule.ID != "github-pat" {
		t.Fatalf("line after block: %+v", r5)
	}
}

func TestLineScannerBlockOnOneJSONLine(t *testing.T) {
	ls := NewLineScanner(rules.MustLoad())
	line := `{"key":"` + pemHeader() + `\nMIIBogIBAAJBAK\n` + pemFooter() + `"}`
	r := ls.Next([]byte(line))
	if len(r.Matches) != 1 || r.Matches[0].Rule.ID != "private-key" {
		t.Fatalf("expected one private-key match, got %+v", r.Matches)
	}
	if r.BlockRule != nil {
		t.Fatal("single line block must not open block state")
	}
	next := ls.Next([]byte("plain " + fakeGitHubPAT()))
	if next.BlockRule != nil || len(next.Matches) != 1 {
		t.Fatalf("scanner stayed in block state after a single line block: %+v", next)
	}
}

func TestLineScannerHeaderInsideJSONStringDoesNotOpenBlock(t *testing.T) {
	ls := NewLineScanner(rules.MustLoad())
	line := `{"text":"the file starts with ` + pemHeader() + ` and continues"}`
	r := ls.Next([]byte(line))
	if len(r.Matches) != 1 {
		t.Fatalf("expected the header to be reported once, got %d", len(r.Matches))
	}
	if r.BlockRule != nil {
		t.Fatal("block state must not open on a JSON line")
	}
	next := ls.Next([]byte(`{"text":"` + fakeGitHubPAT() + `"}`))
	if next.BlockRule != nil || len(next.Matches) != 1 {
		t.Fatalf("next record was swallowed by block state: %+v", next)
	}
}

func TestReaderLineAndColumn(t *testing.T) {
	pat := fakeGitHubPAT()
	ant := fakeAnthropicKey()
	input := "x " + pat + "\nnothing here\n" + ant + "\n"
	type hit struct {
		line, col int
		id        string
	}
	var hits []hit
	err := Reader(context.Background(), Options{Rules: rules.MustLoad()}, strings.NewReader(input), func(line, col int, m rules.Match) {
		hits = append(hits, hit{line, col, m.Rule.ID})
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []hit{{1, 3, "github-pat"}, {3, 1, "anthropic-api-key"}}
	if len(hits) != len(want) {
		t.Fatalf("hits = %+v, want %+v", hits, want)
	}
	for i := range want {
		if hits[i] != want[i] {
			t.Errorf("hit %d = %+v, want %+v", i, hits[i], want[i])
		}
	}
}

func TestFileBinaryDetection(t *testing.T) {
	dir := t.TempDir()
	pat := fakeGitHubPAT()
	content := "header\x00binary\n" + pat + "\n"
	txt := filepath.Join(dir, "blob.txt")
	write(t, txt, content)
	jsonl := filepath.Join(dir, "log.jsonl")
	write(t, jsonl, content)
	opts := Options{Rules: rules.MustLoad()}
	fs, err := File(context.Background(), opts, target(t, txt, sources.KindText))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("text file with NUL should be skipped, got %d findings", len(fs))
	}
	fs, err = File(context.Background(), opts, target(t, jsonl, sources.KindJSONL))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Errorf("jsonl file with NUL should still be scanned, got %d findings", len(fs))
	}
}

func TestTargetsParallelSortedAndDeduplicated(t *testing.T) {
	dir := t.TempDir()
	pat := fakeGitHubPAT()
	var targets []sources.Target
	var total int64
	for _, name := range []string{"c.txt", "a.txt", "b.txt"} {
		p := filepath.Join(dir, name)
		write(t, p, "token "+pat+"\n")
		tg := target(t, p, sources.KindText)
		total += tg.Size
		targets = append(targets, tg)
	}
	fs, st := Targets(context.Background(), Options{Rules: rules.MustLoad(), Workers: 3}, targets)
	if st.Files != 3 || st.Bytes != total {
		t.Errorf("stats = files %d bytes %d, want 3 and %d", st.Files, st.Bytes, total)
	}
	if len(st.Errors) != 0 {
		t.Errorf("unexpected errors: %+v", st.Errors)
	}
	if len(fs) != 3 {
		t.Fatalf("got %d findings, want 3", len(fs))
	}
	for i := 1; i < len(fs); i++ {
		if fs[i-1].Path > fs[i].Path {
			t.Errorf("findings not sorted: %s before %s", fs[i-1].Path, fs[i].Path)
		}
	}
	for _, f := range fs {
		if f.Masked == pat || strings.Contains(f.Masked, pat[6:20]) {
			t.Error("masked preview leaks the secret")
		}
		if f.Fingerprint != rules.Fingerprint(pat) {
			t.Error("fingerprint mismatch")
		}
	}
}

func TestTargetsDeduplicatesChunkOverlap(t *testing.T) {
	dir := t.TempDir()
	pat := fakeGitHubPAT()
	// Place the secret inside the overlap window at the end of the first
	// chunk so it is reported by two chunks with the same column.
	pos := readBuf - 2000
	var b strings.Builder
	b.WriteString(strings.Repeat("q", pos-1))
	b.WriteString(" " + pat + " ")
	b.WriteString(strings.Repeat("q", 50*1024))
	b.WriteString("\n")
	p := filepath.Join(dir, "long.txt")
	write(t, p, b.String())
	fs, st := Targets(context.Background(), Options{Rules: rules.MustLoad(), MaxLine: 8192}, []sources.Target{target(t, p, sources.KindText)})
	if len(st.Errors) != 0 {
		t.Fatalf("errors: %+v", st.Errors)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want exactly 1 after dedupe", len(fs))
	}
	if fs[0].Line != 1 || fs[0].Column != pos+1 {
		t.Errorf("finding at %d:%d, want 1:%d", fs[0].Line, fs[0].Column, pos+1)
	}
}

func TestTargetsMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.txt")
	tg := sources.Target{Tool: "test", Kind: sources.KindText, Path: missing}
	fs, st := Targets(context.Background(), Options{Rules: rules.MustLoad()}, []sources.Target{tg})
	if len(fs) != 0 {
		t.Errorf("unexpected findings: %+v", fs)
	}
	if len(st.Errors) != 1 || st.Errors[0].Path != missing {
		t.Fatalf("errors = %+v, want one for %s", st.Errors, missing)
	}
}

func makeDB(t *testing.T, path string, stmts ...func(db *sql.DB)) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range stmts {
		s(db)
	}
}

func exec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func TestSQLiteScan(t *testing.T) {
	dir := t.TempDir()
	pat := fakeGitHubPAT()
	path := filepath.Join(dir, "state.vscdb")
	makeDB(t, path, func(db *sql.DB) {
		exec(t, db, `CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)`)
		exec(t, db, `CREATE TABLE cursorDiskKV (key TEXT, value TEXT)`)
		exec(t, db, `CREATE TABLE bin (key TEXT, value BLOB)`)
		exec(t, db, `INSERT INTO ItemTable VALUES (?, ?)`, "composerData:abc", []byte(`{"text":"my token `+pat+`"}`))
		exec(t, db, `INSERT INTO ItemTable VALUES (?, ?)`, "workbench.clean", []byte(`{"text":"nothing to see"}`))
		exec(t, db, `INSERT INTO cursorDiskKV VALUES (?, ?)`, "bubbleId:1", `{"text":"hello world, no secrets"}`)
		exec(t, db, `INSERT INTO bin VALUES (?, ?)`, "image", []byte("PNG\x00\x00\x00"+pat))
	})
	fs, err := SQLite(context.Background(), Options{Rules: rules.MustLoad()}, target(t, path, sources.KindSQLite))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Record != "ItemTable/composerData:abc" {
		t.Errorf("record = %q", f.Record)
	}
	if f.Line != 0 || f.Column != 0 {
		t.Errorf("sqlite findings must not carry line numbers, got %d:%d", f.Line, f.Column)
	}
	if f.RuleID != "github-pat" || f.Secret != pat {
		t.Errorf("rule %q secret mismatch", f.RuleID)
	}
}

func TestScanCellOffsets(t *testing.T) {
	pat := fakeGitHubPAT()
	ant := fakeAnthropicKey()
	cell := []byte(pat + "\nxx " + ant)
	ms := scanCell(rules.MustLoad(), cell)
	if len(ms) != 2 {
		t.Fatalf("got %d matches, want 2", len(ms))
	}
	if ms[0].Start != 0 || ms[0].End != len(pat) {
		t.Errorf("first match at %d..%d", ms[0].Start, ms[0].End)
	}
	wantStart := len(pat) + 1 + 3
	if ms[1].Start != wantStart || string(cell[ms[1].Start:ms[1].End]) != ant {
		t.Errorf("second match at %d, want %d", ms[1].Start, wantStart)
	}
}

func TestPathWalksDirectoryAndSkipsGit(t *testing.T) {
	dir := t.TempDir()
	pat := fakeGitHubPAT()
	write(t, filepath.Join(dir, "nested", "deep", "notes.md"), "key "+pat+"\n")
	write(t, filepath.Join(dir, ".git", "config"), "token "+pat+"\n")
	write(t, filepath.Join(dir, "clean.txt"), "nothing\n")
	fs, st, err := Path(context.Background(), Options{Rules: rules.MustLoad()}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Files != 2 {
		t.Errorf("scanned %d files, want 2 (the .git file must be skipped)", st.Files)
	}
	if len(fs) != 1 || !strings.HasSuffix(fs[0].Path, filepath.Join("nested", "deep", "notes.md")) {
		t.Fatalf("findings = %+v", fs)
	}
	single, _, err := Path(context.Background(), Options{Rules: rules.MustLoad()}, filepath.Join(dir, "nested", "deep", "notes.md"))
	if err != nil || len(single) != 1 {
		t.Fatalf("single file: %v, %d findings", err, len(single))
	}
	if _, _, err := Path(context.Background(), Options{}, filepath.Join(dir, "missing")); err == nil {
		t.Error("missing path must return an error")
	}
}

func TestFindingLocation(t *testing.T) {
	if got := (Finding{Line: 3, Column: 7}).Location(); got != "3:7" {
		t.Errorf("Location = %q", got)
	}
	if got := (Finding{Record: "ItemTable/k"}).Location(); got != "ItemTable/k" {
		t.Errorf("Location = %q", got)
	}
	if got := (Finding{}).Location(); got != "" {
		t.Errorf("Location = %q", got)
	}
	_ = time.Now()
}
