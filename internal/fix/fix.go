// Package fix redacts secrets in place while keeping JSONL records, JSON
// documents and SQLite rows valid, and writes a backup of every file it
// touches.
package fix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Arthur031221/agentleaks/internal/rules"
	"github.com/Arthur031221/agentleaks/internal/scan"
	"github.com/Arthur031221/agentleaks/internal/sources"
)

// Options controls a fix run.
type Options struct {
	Rules     *rules.Set
	DryRun    bool
	NoBackup  bool
	BackupDir string // default <home>/.agentleaks/backups/<timestamp>
	Home      string
	MaxLine   int
	// IncludeCredentialStores allows rewriting the tools' own credential
	// files. Off by default because it logs the user out.
	IncludeCredentialStores bool
}

// Result describes what happened to one file.
type Result struct {
	Path     string `json:"path"`
	Tool     string `json:"tool"`
	Redacted int    `json:"redacted"`
	Kept     int    `json:"kept,omitempty"` // records left untouched because redaction would break them
	Backup   string `json:"backup,omitempty"`
	Skipped  string `json:"skipped,omitempty"`
	Error    string `json:"error,omitempty"`
	DryRun   bool   `json:"dry_run"`
}

const defaultMaxLine = 32 << 20

func (o Options) fill() Options {
	if o.Rules == nil {
		o.Rules = rules.MustLoad()
	}
	if o.MaxLine <= 0 {
		o.MaxLine = defaultMaxLine
	}
	if o.Home == "" {
		o.Home, _ = os.UserHomeDir()
	}
	if o.BackupDir == "" && !o.NoBackup {
		o.BackupDir = filepath.Join(o.Home, ".agentleaks", "backups", time.Now().Format("20060102-150405"))
	}
	return o
}

// Run redacts every target in order.
func Run(ctx context.Context, opts Options, targets []sources.Target) []Result {
	opts = opts.fill()
	var out []Result
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		out = append(out, One(ctx, opts, t))
	}
	return out
}

// One redacts a single target.
func One(ctx context.Context, opts Options, t sources.Target) Result {
	opts = opts.fill()
	res := Result{Path: t.Path, Tool: t.Tool, DryRun: opts.DryRun}
	if t.Credential && !opts.IncludeCredentialStores {
		res.Skipped = "credential store, pass --include-credential-stores to rewrite"
		return res
	}
	var err error
	if t.Kind == sources.KindSQLite {
		err = fixSQLite(ctx, opts, t, &res)
	} else {
		err = fixFile(ctx, opts, t, &res)
	}
	if err != nil {
		res.Error = err.Error()
		if !opts.DryRun {
			// Nothing was applied: the file is only replaced after the
			// backup and the temp file both succeed.
			res.Redacted = 0
		}
	}
	return res
}

// RedactLine rewrites one line. It returns the new line, the number of
// secrets replaced, and whether the line is a continuation of a private
// key block that should be blanked.
func RedactLine(ls *scan.LineScanner, line []byte) ([]byte, int) {
	res := ls.Next(line)
	if res.BlockRule != nil {
		return nil, 0
	}
	if len(res.Matches) == 0 {
		return line, 0
	}
	var out []byte
	pos := 0
	n := 0
	for _, m := range res.Matches {
		if m.Start < pos {
			continue // covered by a previous block extent
		}
		end := m.End
		if m.Rule.IsBlock() {
			end = blockExtent(line, m.Rule.BlockEnd, m.End)
		}
		out = append(out, line[pos:m.Start]...)
		out = append(out, rules.Redaction(m.Rule.ID)...)
		pos = end
		n++
	}
	out = append(out, line[pos:]...)
	return out, n
}

// blockExtent returns where the redaction of a private key block that
// starts at from should stop on this line. If the END marker is on the
// line, everything up to it goes. Otherwise, inside a JSON string, the
// extent stops at the closing quote so the record stays valid, and in
// plain text it runs to the end of the line.
func blockExtent(line []byte, blockEnd interface{ FindIndex([]byte) []int }, from int) int {
	if loc := blockEnd.FindIndex(line[from:]); loc != nil {
		return from + loc[1]
	}
	for i := from; i < len(line); i++ {
		if line[i] == '\\' {
			i++
			continue
		}
		if line[i] == '"' {
			return i
		}
	}
	return len(line)
}

func fixFile(ctx context.Context, opts Options, t sources.Target, res *Result) error {
	in, err := os.Open(t.Path)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	var tmp *os.File
	if !opts.DryRun {
		tmp, err = os.CreateTemp(filepath.Dir(t.Path), ".agentleaks-tmp-*")
		if err != nil {
			return err
		}
		defer func() {
			tmp.Close()
			os.Remove(tmp.Name())
		}()
	}
	ls := scan.NewLineScanner(opts.Rules)
	jsonl := t.Kind == sources.KindJSONL
	structured := jsonl || t.Kind == sources.KindJSON
	var w io.Writer = io.Discard
	if tmp != nil {
		w = tmp
	}
	// Tools append records to these files, so a trailing newline must
	// survive the rewrite or the next record is glued to the last line.
	endsWithNewline := false
	if info.Size() > 0 {
		var last [1]byte
		if _, err := in.ReadAt(last[:], info.Size()-1); err == nil && last[0] == '\n' {
			endsWithNewline = true
		}
	}
	bw := newBufWriter(w)
	err = scan.ReadLines(in, opts.MaxLine, func(lineNo, offset, overlapLen int, line []byte) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		newLine, n := RedactLine(ls, line)
		if newLine == nil && len(line) > 0 && structured {
			// Never blank a whole record of a structured file.
			newLine = line
		}
		if n > 0 && jsonl && offset == 0 && json.Valid(line) && !json.Valid(newLine) {
			// Never write a JSONL record that no longer parses.
			newLine = line
			res.Kept += n
			n = 0
		}
		res.Redacted += n
		if offset == 0 && lineNo > 1 {
			_ = bw.WriteByte('\n')
		}
		// This chunk repeats overlapLen bytes already written by the
		// previous chunk of the same line, so only the new tail goes out.
		if overlapLen > 0 && overlapLen <= len(newLine) {
			newLine = newLine[overlapLen:]
		}
		bw.Write(newLine)
		return nil
	})
	if err != nil {
		return err
	}
	if endsWithNewline {
		_ = bw.WriteByte('\n')
	}
	if opts.DryRun || res.Redacted == 0 {
		return nil
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	// Whole-document validation for pretty printed JSON files.
	if t.Kind == sources.KindJSON && info.Size() < 256<<20 {
		orig, err := os.ReadFile(t.Path)
		if err != nil {
			return err
		}
		if json.Valid(orig) {
			out, err := os.ReadFile(tmp.Name())
			if err != nil {
				return err
			}
			if !json.Valid(out) {
				res.Kept = res.Redacted
				res.Redacted = 0
				return errors.New("redaction would break the JSON document, file left untouched")
			}
		}
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if !opts.NoBackup {
		b, err := backup(opts, t.Path)
		if err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		res.Backup = b
	}
	if err := os.Chmod(tmp.Name(), info.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), t.Path); err != nil {
		return err
	}
	// Keep the original modification time so tools that order sessions by
	// mtime do not reshuffle their history.
	_ = os.Chtimes(t.Path, time.Now(), info.ModTime())
	return nil
}

func fixSQLite(ctx context.Context, opts Options, t sources.Target, res *Result) error {
	type change struct {
		row  scan.Row
		text []byte
	}
	var changes []change
	// Detect on a read-only handle first so a locked database still reports.
	ro, err := scan.OpenReadOnly(t.Path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	err = scan.WalkText(ctx, ro, func(row scan.Row, text []byte) error {
		newText, n := redactCell(opts.Rules, text)
		if n == 0 {
			return nil
		}
		if json.Valid(text) && !json.Valid(newText) {
			res.Kept += n
			return nil
		}
		res.Redacted += n
		changes = append(changes, change{row: row, text: newText})
		return nil
	})
	ro.Close()
	if err != nil {
		return err
	}
	if opts.DryRun || len(changes) == 0 {
		return nil
	}
	if !opts.NoBackup {
		b, err := backupSQLite(opts, t.Path)
		if err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		res.Backup = b
	}
	db, err := scan.OpenReadWrite(t.Path)
	if err != nil {
		return fmt.Errorf("open for write (close the application first): %w", err)
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, c := range changes {
		q := fmt.Sprintf(`UPDATE %s SET %s = ? WHERE rowid = ?`, quoteIdent(c.row.Table), quoteIdent(c.row.Column))
		var val any = string(c.text)
		if c.row.Blob {
			val = c.text
		}
		if _, err := tx.ExecContext(ctx, q, val, c.row.RowID); err != nil {
			tx.Rollback()
			return fmt.Errorf("update %s: %w", c.row.Record(), err)
		}
	}
	return tx.Commit()
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// redactCell handles a cell that may span several lines.
func redactCell(set *rules.Set, text []byte) ([]byte, int) {
	ls := scan.NewLineScanner(set)
	var out []byte
	total := 0
	start := 0
	first := true
	for start <= len(text) {
		end := start
		for end < len(text) && text[end] != '\n' {
			end++
		}
		line, n := RedactLine(ls, text[start:end])
		total += n
		if !first {
			out = append(out, '\n')
		}
		first = false
		out = append(out, line...)
		if end >= len(text) {
			break
		}
		start = end + 1
	}
	if total == 0 {
		return text, 0
	}
	return out, total
}

// backup copies path under the backup directory, mirroring its absolute path.
func backup(opts Options, path string) (string, error) {
	dst := backupPath(opts, path)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	if err := copyFile(path, dst); err != nil {
		return "", err
	}
	return dst, nil
}

func backupSQLite(opts Options, path string) (string, error) {
	dst := backupPath(opts, path)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	// VACUUM INTO produces a consistent single-file copy even in WAL mode.
	db, err := scan.OpenReadOnly(path)
	if err == nil {
		_, verr := db.Exec(`VACUUM INTO ?`, dst)
		db.Close()
		if verr == nil {
			_ = os.Chmod(dst, 0o600)
			return dst, nil
		}
		os.Remove(dst)
	}
	if err := copyFile(path, dst); err != nil {
		return "", err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			_ = copyFile(path+suffix, dst+suffix)
		}
	}
	return dst, nil
}

func backupPath(opts Options, path string) string {
	clean := filepath.Clean(path)
	vol := filepath.VolumeName(clean)
	rel := strings.TrimPrefix(clean[len(vol):], string(filepath.Separator))
	return filepath.Join(opts.BackupDir, rel)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

type bufWriter struct {
	w   io.Writer
	buf bytes.Buffer
}

func newBufWriter(w io.Writer) *bufWriter { return &bufWriter{w: w} }

func (b *bufWriter) Write(p []byte) {
	b.buf.Write(p)
	if b.buf.Len() > 1<<20 {
		_ = b.Flush()
	}
}

func (b *bufWriter) WriteByte(c byte) error { return b.buf.WriteByte(c) }

func (b *bufWriter) Flush() error {
	if b.buf.Len() == 0 {
		return nil
	}
	_, err := b.w.Write(b.buf.Bytes())
	b.buf.Reset()
	return err
}
