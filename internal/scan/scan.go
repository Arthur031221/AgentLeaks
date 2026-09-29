// Package scan streams files and SQLite stores through the rule set and
// returns findings. It never loads a whole file into memory.
package scan

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/Arthur031221/agentleaks/internal/rules"
	"github.com/Arthur031221/agentleaks/internal/sources"
)

// Finding is one secret at one location.
type Finding struct {
	RuleID      string    `json:"rule"`
	Provider    string    `json:"provider"`
	Severity    string    `json:"severity"`
	Tool        string    `json:"tool"`
	ToolName    string    `json:"tool_name"`
	Label       string    `json:"label"`
	Path        string    `json:"path"`
	Line        int       `json:"line,omitempty"`
	Column      int       `json:"column,omitempty"`
	Record      string    `json:"record,omitempty"`
	Masked      string    `json:"masked"`
	Fingerprint string    `json:"fingerprint"`
	ModTime     time.Time `json:"modified"`
	Verify      string    `json:"-"`
	Credential  bool      `json:"credential_store,omitempty"`
	Status      string    `json:"status,omitempty"`
	StatusInfo  string    `json:"status_detail,omitempty"`
	// Secret is kept in memory for fix and verify. It is never serialized.
	Secret string `json:"-"`
}

// Location renders the position for tables.
func (f Finding) Location() string {
	if f.Record != "" {
		return f.Record
	}
	if f.Line > 0 {
		return fmt.Sprintf("%d:%d", f.Line, f.Column)
	}
	return ""
}

// Options controls a scan.
type Options struct {
	Rules   *rules.Set
	Workers int
	// MaxLine caps the bytes buffered for one line. Longer lines are scanned
	// in chunks with a small overlap. Default 32 MiB.
	MaxLine int
	// SkipCredentialStores drops findings in the tools' own credential files.
	SkipCredentialStores bool
	// OnFile is called after each file finishes, for progress output.
	OnFile func(t sources.Target, n int, err error)
}

// Stats summarises a scan.
type Stats struct {
	Files    int           `json:"files"`
	Bytes    int64         `json:"bytes"`
	Duration time.Duration `json:"-"`
	Errors   []FileError   `json:"errors,omitempty"`
}

// FileError records a file that could not be scanned.
type FileError struct {
	Path string `json:"path"`
	Err  string `json:"error"`
}

const (
	defaultMaxLine = 32 << 20
	overlap        = 4096
	readBuf        = 256 << 10
)

func (o Options) fill() Options {
	if o.Rules == nil {
		o.Rules = rules.MustLoad()
	}
	if o.Workers <= 0 {
		o.Workers = runtime.NumCPU()
	}
	if o.MaxLine <= 0 {
		o.MaxLine = defaultMaxLine
	}
	return o
}

// Targets scans every target with a worker pool.
func Targets(ctx context.Context, opts Options, targets []sources.Target) ([]Finding, Stats) {
	opts = opts.fill()
	start := time.Now()
	var (
		mu       sync.Mutex
		findings []Finding
		stats    Stats
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, opts.Workers)
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t sources.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			fs, err := File(ctx, opts, t)
			mu.Lock()
			stats.Files++
			stats.Bytes += t.Size
			if err != nil {
				stats.Errors = append(stats.Errors, FileError{Path: t.Path, Err: err.Error()})
			}
			findings = append(findings, fs...)
			mu.Unlock()
			if opts.OnFile != nil {
				opts.OnFile(t, len(fs), err)
			}
		}(t)
	}
	wg.Wait()
	stats.Duration = time.Since(start)
	Sort(findings)
	return dedupe(findings), stats
}

// Sort orders findings by tool, path, line, column.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Record != b.Record {
			return a.Record < b.Record
		}
		return a.Column < b.Column
	})
}

func dedupe(fs []Finding) []Finding {
	type key struct {
		path, rec, fp string
		line, col     int
	}
	seen := map[key]bool{}
	out := fs[:0]
	for _, f := range fs {
		k := key{f.Path, f.Record, f.Fingerprint, f.Line, f.Column}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

// File scans one target according to its kind.
func File(ctx context.Context, opts Options, t sources.Target) ([]Finding, error) {
	opts = opts.fill()
	if t.Credential && opts.SkipCredentialStores {
		return nil, nil
	}
	if t.Kind == sources.KindSQLite {
		return SQLite(ctx, opts, t)
	}
	f, err := os.Open(t.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if t.Kind == sources.KindText && looksBinary(f) {
		return nil, nil
	}
	var out []Finding
	err = Reader(ctx, opts, f, func(line, col int, m rules.Match) {
		out = append(out, newFinding(t, m, line, col, ""))
	})
	return out, err
}

func newFinding(t sources.Target, m rules.Match, line, col int, record string) Finding {
	return Finding{
		RuleID:      m.Rule.ID,
		Provider:    m.Rule.Provider,
		Severity:    m.Rule.Severity,
		Tool:        t.Tool,
		ToolName:    t.ToolName,
		Label:       t.Label,
		Path:        t.Path,
		Line:        line,
		Column:      col,
		Record:      record,
		Masked:      rules.Mask(m.Secret),
		Fingerprint: rules.Fingerprint(m.Secret),
		ModTime:     t.ModTime,
		Verify:      m.Rule.Verify,
		Credential:  t.Credential,
		Secret:      m.Secret,
	}
}

// looksBinary samples the start of a file for NUL bytes and rewinds.
func looksBinary(f *os.File) bool {
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	_, _ = f.Seek(0, io.SeekStart)
	return bytes.IndexByte(buf[:n], 0) >= 0
}

// LineScanner applies the rule set line by line and tracks multi-line
// private key blocks. Fix reuses it so detection and redaction agree.
type LineScanner struct {
	set     *rules.Set
	inBlock *rules.Rule
}

// NewLineScanner returns a scanner over the given rule set.
func NewLineScanner(set *rules.Set) *LineScanner { return &LineScanner{set: set} }

// LineResult describes one scanned line.
type LineResult struct {
	Matches []rules.Match
	// BlockRule is set when the whole line sits inside a private key block
	// that opened on an earlier line (the block header itself is reported
	// as a normal match). Fix blanks such lines.
	BlockRule *rules.Rule
	// BlockEnds is set on the line that closes a block.
	BlockEnds bool
}

// Next scans one line.
func (s *LineScanner) Next(line []byte) LineResult {
	var res LineResult
	if s.inBlock != nil {
		res.BlockRule = s.inBlock
		if s.inBlock.BlockEnd.Match(line) {
			res.BlockEnds = true
			s.inBlock = nil
		}
		return res
	}
	res.Matches = s.set.Scan(line)
	for _, m := range res.Matches {
		if m.Rule.IsBlock() && !looksLikeJSON(line) {
			// The block closes on this line when the END marker follows the
			// header. A header inside a JSON record never opens a block:
			// the key body would be escaped into the same line, and a bare
			// header there is text about a key, not a key.
			if loc := m.Rule.BlockEnd.FindIndex(line[m.End:]); loc == nil {
				s.inBlock = m.Rule
			}
		}
	}
	return res
}

// looksLikeJSON reports whether a line is a JSON document or array.
func looksLikeJSON(line []byte) bool {
	for _, c := range line {
		switch c {
		case ' ', '\t', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// Reader streams r line by line and reports matches.
func Reader(ctx context.Context, opts Options, r io.Reader, fn func(line, col int, m rules.Match)) error {
	opts = opts.fill()
	ls := NewLineScanner(opts.Rules)
	return ReadLines(r, opts.MaxLine, func(lineNo, offset int, line []byte) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		res := ls.Next(line)
		for _, m := range res.Matches {
			fn(lineNo, offset+m.Start+1, m)
		}
		return nil
	})
}

// ReadLines calls fn for each line without the trailing newline. Lines
// longer than maxLine are delivered in chunks that share the line number,
// with offset giving the chunk's byte position within the line.
func ReadLines(r io.Reader, maxLine int, fn func(lineNo, offset int, line []byte) error) error {
	br := bufio.NewReaderSize(r, readBuf)
	lineNo := 0
	offset := 0
	var acc []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(frag) > 0 {
			if offset == 0 && len(acc) == 0 {
				lineNo++
			}
			complete := frag[len(frag)-1] == '\n'
			if complete {
				frag = frag[:len(frag)-1]
				if len(frag) > 0 && frag[len(frag)-1] == '\r' {
					frag = frag[:len(frag)-1]
				}
			}
			acc = append(acc, frag...)
			if complete {
				if e := fn(lineNo, offset, acc); e != nil {
					return e
				}
				acc = acc[:0]
				offset = 0
			} else if len(acc) >= maxLine {
				if e := fn(lineNo, offset, acc); e != nil {
					return e
				}
				keep := overlap
				if keep > len(acc) {
					keep = len(acc)
				}
				offset += len(acc) - keep
				copy(acc, acc[len(acc)-keep:])
				acc = acc[:keep]
			}
		}
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if errors.Is(err, io.EOF) {
				if len(acc) > 0 {
					if e := fn(lineNo, offset, acc); e != nil {
						return e
					}
				}
				return nil
			}
			return err
		}
	}
}

// Path scans an arbitrary file or directory supplied by the user.
func Path(ctx context.Context, opts Options, root string) ([]Finding, Stats, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, Stats{}, err
	}
	var targets []sources.Target
	add := func(p string, fi os.FileInfo) {
		targets = append(targets, sources.Target{
			Tool: "path", ToolName: "path", Label: "user path", Kind: sources.KindForPath(p),
			Path: p, Size: fi.Size(), ModTime: fi.ModTime(),
		})
	}
	if !info.IsDir() {
		add(root, info)
	} else {
		err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if p != root && (d.Name() == ".git" || d.Name() == "node_modules") {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			add(p, fi)
			return nil
		})
		if err != nil {
			return nil, Stats{}, err
		}
	}
	fs, st := Targets(ctx, opts, targets)
	return fs, st, nil
}
