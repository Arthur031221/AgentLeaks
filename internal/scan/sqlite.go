package scan

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	"github.com/Arthur031221/agentleaks/internal/rules"
	"github.com/Arthur031221/agentleaks/internal/sources"
	_ "modernc.org/sqlite"
)

// Row identifies one text cell in a SQLite store.
type Row struct {
	Table  string
	Column string
	RowID  int64
	Key    string // value of a "key" column when the table has one
	Blob   bool   // the cell was stored as a blob rather than text
}

// Record renders the row for tables and JSON output.
func (r Row) Record() string {
	if r.Key != "" {
		k := r.Key
		if len(k) > 48 {
			k = k[:45] + "..."
		}
		return fmt.Sprintf("%s/%s", r.Table, k)
	}
	return fmt.Sprintf("%s/rowid=%d/%s", r.Table, r.RowID, r.Column)
}

// OpenReadOnly opens a SQLite file without taking write locks.
func OpenReadOnly(path string) (*sql.DB, error) {
	dsn := "file:" + url.PathEscape(path) + "?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// OpenReadWrite opens a SQLite file for in-place redaction.
func OpenReadWrite(path string) (*sql.DB, error) {
	dsn := "file:" + url.PathEscape(path) + "?mode=rw&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Tables lists user tables in the database.
func Tables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// WalkText calls fn for every text or blob cell that decodes as text.
// Tables without a rowid (WITHOUT ROWID or virtual tables) are skipped
// because the fix path needs a rowid to update in place.
func WalkText(ctx context.Context, db *sql.DB, fn func(row Row, text []byte) error) error {
	tables, err := Tables(ctx, db)
	if err != nil {
		return err
	}
	for _, table := range tables {
		if err := walkTable(ctx, db, table, fn); err != nil {
			// A table that cannot be read (virtual, corrupt, no rowid) is
			// skipped rather than failing the whole store.
			continue
		}
	}
	return nil
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func walkTable(ctx context.Context, db *sql.DB, table string, fn func(row Row, text []byte) error) error {
	rows, err := db.QueryContext(ctx, `SELECT rowid, * FROM `+quoteIdent(table))
	if err != nil {
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	keyIdx := -1
	for i, c := range cols {
		if i > 0 && strings.EqualFold(c, "key") {
			keyIdx = i
		}
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		rowid, _ := vals[0].(int64)
		key := ""
		if keyIdx >= 0 {
			key = asString(vals[keyIdx])
		}
		for i := 1; i < len(cols); i++ {
			var text []byte
			blob := false
			switch v := vals[i].(type) {
			case string:
				text = []byte(v)
			case []byte:
				text = v
				blob = true
			default:
				continue
			}
			if len(text) < 8 || !isText(text) {
				continue
			}
			if err := fn(Row{Table: table, Column: cols[i], RowID: rowid, Key: key, Blob: blob}, text); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case int64:
		return fmt.Sprint(t)
	}
	return ""
}

// isText rejects cells with NUL bytes in their first 4 KiB.
func isText(b []byte) bool {
	n := len(b)
	if n > 4096 {
		n = 4096
	}
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return false
		}
	}
	return true
}

// SQLite scans every text cell of a SQLite store.
func SQLite(ctx context.Context, opts Options, t sources.Target) ([]Finding, error) {
	opts = opts.fill()
	db, err := OpenReadOnly(t.Path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()
	var out []Finding
	err = WalkText(ctx, db, func(row Row, text []byte) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, m := range scanCell(opts.Rules, text) {
			f := newFinding(t, m, 0, 0, row.Record())
			out = append(out, f)
		}
		return nil
	})
	return out, err
}

// scanCell runs the line scanner over a cell that may contain newlines.
func scanCell(set *rules.Set, text []byte) []rules.Match {
	ls := NewLineScanner(set)
	var out []rules.Match
	start := 0
	for start <= len(text) {
		end := start
		for end < len(text) && text[end] != '\n' {
			end++
		}
		res := ls.Next(text[start:end])
		for _, m := range res.Matches {
			m.Start += start
			m.End += start
			out = append(out, m)
		}
		if end >= len(text) {
			break
		}
		start = end + 1
	}
	return out
}
