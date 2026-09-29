// Package output renders findings as a terminal table, JSON or SARIF.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Arthur031221/agentleaks/internal/rules"
	"github.com/Arthur031221/agentleaks/internal/scan"
	"github.com/Arthur031221/agentleaks/internal/sources"
)

// Report is the JSON document written by scan --json and report.
type Report struct {
	Version     string           `json:"agentleaks_version"`
	GeneratedAt time.Time        `json:"generated_at"`
	Summary     Summary          `json:"summary"`
	Tools       []sources.Status `json:"tools"`
	Findings    []scan.Finding   `json:"findings"`
	Errors      []scan.FileError `json:"errors,omitempty"`
}

// Summary holds the headline counts.
type Summary struct {
	Findings     int   `json:"findings"`
	Distinct     int   `json:"distinct_secrets"`
	Files        int   `json:"files_with_findings"`
	Tools        int   `json:"tools_with_findings"`
	Live         int   `json:"live,omitempty"`
	Dead         int   `json:"dead,omitempty"`
	ScannedFiles int   `json:"scanned_files"`
	ScannedBytes int64 `json:"scanned_bytes"`
	DurationMS   int64 `json:"duration_ms"`
}

// Summarize computes the summary block.
func Summarize(fs []scan.Finding, st scan.Stats) Summary {
	s := Summary{Findings: len(fs), ScannedFiles: st.Files, ScannedBytes: st.Bytes, DurationMS: st.Duration.Milliseconds()}
	distinct := map[string]bool{}
	files := map[string]bool{}
	tools := map[string]bool{}
	for _, f := range fs {
		distinct[f.Fingerprint] = true
		files[f.Path] = true
		tools[f.Tool] = true
		switch f.Status {
		case "live":
			s.Live++
		case "dead":
			s.Dead++
		}
	}
	s.Distinct = len(distinct)
	s.Files = len(files)
	s.Tools = len(tools)
	return s
}

// JSON writes the report.
func JSON(w io.Writer, r Report) error {
	if r.Findings == nil {
		r.Findings = []scan.Finding{}
	}
	if r.Tools == nil {
		r.Tools = []sources.Status{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Group is one table row: one secret in one file.
type Group struct {
	First scan.Finding
	Count int
}

// GroupFindings folds repeated occurrences of one secret in one file.
func GroupFindings(fs []scan.Finding) []Group {
	idx := map[string]int{}
	var groups []Group
	for _, f := range fs {
		k := f.Path + "\x00" + f.Fingerprint
		if i, ok := idx[k]; ok {
			groups[i].Count++
			continue
		}
		idx[k] = len(groups)
		groups = append(groups, Group{First: f, Count: 1})
	}
	return groups
}

// TableOptions controls the terminal table.
type TableOptions struct {
	Home     string
	All      bool // one row per occurrence instead of per secret per file
	Color    bool
	Verified bool
	Width    int
}

// Table renders findings.
func Table(w io.Writer, fs []scan.Finding, opts TableOptions) {
	if len(fs) == 0 {
		return
	}
	type row []string
	head := row{"PROVIDER", "TOOL", "FILE", "WHERE", "PREVIEW", "AGE"}
	if !opts.All {
		head = append(head, "HITS")
	}
	if opts.Verified {
		head = append(head, "STATUS")
	}
	var rows []row
	now := time.Now()
	add := func(f scan.Finding, count int) {
		r := row{f.Provider, f.ToolName, shortPath(opts.Home, f.Path, 44), f.Location(), f.Masked, Age(now, f.ModTime)}
		if !opts.All {
			r = append(r, fmt.Sprint(count))
		}
		if opts.Verified {
			s := f.Status
			if s == "" {
				s = "-"
			}
			r = append(r, s)
		}
		rows = append(rows, r)
	}
	if opts.All {
		for _, f := range fs {
			add(f, 1)
		}
	} else {
		for _, g := range GroupFindings(fs) {
			add(g.First, g.Count)
		}
	}
	widths := make([]int, len(head))
	for i, h := range head {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	line := func(r row, bold bool) {
		var b strings.Builder
		for i, c := range r {
			if i > 0 {
				b.WriteString("  ")
			}
			b.WriteString(c)
			if i < len(r)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-len(c)))
			}
		}
		s := b.String()
		if bold && opts.Color {
			s = "\x1b[1m" + s + "\x1b[0m"
		}
		fmt.Fprintln(w, s)
	}
	line(head, true)
	for _, r := range rows {
		if opts.Verified && opts.Color {
			last := r[len(r)-1]
			switch last {
			case "live":
				r[len(r)-1] = "\x1b[31m" + last + "\x1b[0m"
			case "dead":
				r[len(r)-1] = "\x1b[32m" + last + "\x1b[0m"
			}
		}
		line(r, false)
	}
}

func shortPath(home, p string, max int) string {
	s := sources.Shorten(home, p)
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-(max-3):]
}

// Age renders a modification time as a short relative duration.
func Age(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d < 60*24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d < 365*24*time.Hour:
		return fmt.Sprintf("%dmo", int(d.Hours()/24/30))
	default:
		return fmt.Sprintf("%dy", int(d.Hours()/24/365))
	}
}

// SummaryLine renders the one-line result under the table.
func SummaryLine(fs []scan.Finding, st scan.Stats, statuses []sources.Status) string {
	s := Summarize(fs, st)
	found := 0
	for _, t := range statuses {
		if t.Found {
			found++
		}
	}
	if len(fs) == 0 {
		return fmt.Sprintf("No secrets found. Scanned %d files (%s) from %d tools in %s.",
			st.Files, Bytes(st.Bytes), found, st.Duration.Round(time.Millisecond))
	}
	msg := fmt.Sprintf("%d secrets (%d distinct) in %d files across %d tools. Scanned %d files (%s) from %d tools in %s.",
		s.Findings, s.Distinct, s.Files, s.Tools, st.Files, Bytes(st.Bytes), found, st.Duration.Round(time.Millisecond))
	if s.Live > 0 || s.Dead > 0 {
		msg += fmt.Sprintf(" Verified: %d live, %d dead.", s.Live, s.Dead)
	}
	return msg
}

// Bytes renders a byte count.
func Bytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// SARIF writes a SARIF 2.1.0 log.
func SARIF(w io.Writer, fs []scan.Finding, set *rules.Set, version string) error {
	type region struct {
		StartLine   int `json:"startLine,omitempty"`
		StartColumn int `json:"startColumn,omitempty"`
	}
	type artifact struct {
		URI string `json:"uri"`
	}
	type physical struct {
		Artifact artifact `json:"artifactLocation"`
		Region   *region  `json:"region,omitempty"`
	}
	type location struct {
		Physical physical `json:"physicalLocation"`
	}
	type message struct {
		Text string `json:"text"`
	}
	type result struct {
		RuleID       string            `json:"ruleId"`
		Level        string            `json:"level"`
		Message      message           `json:"message"`
		Locations    []location        `json:"locations"`
		Fingerprints map[string]string `json:"partialFingerprints"`
		Properties   map[string]any    `json:"properties"`
	}
	type desc struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID         string         `json:"id"`
		Name       string         `json:"name"`
		ShortDesc  desc           `json:"shortDescription"`
		Properties map[string]any `json:"properties"`
	}
	type driver struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		InfoURI string `json:"informationUri"`
		Rules   []rule `json:"rules"`
	}
	type tool struct {
		Driver driver `json:"driver"`
	}
	type run struct {
		Tool    tool     `json:"tool"`
		Results []result `json:"results"`
	}
	type log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}
	used := map[string]bool{}
	for _, f := range fs {
		used[f.RuleID] = true
	}
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var rs []rule
	for _, id := range ids {
		r := set.Get(id)
		if r == nil {
			continue
		}
		rs = append(rs, rule{ID: r.ID, Name: r.ID, ShortDesc: desc{Text: r.Description},
			Properties: map[string]any{"provider": r.Provider, "severity": r.Severity}})
	}
	results := make([]result, 0, len(fs))
	for _, f := range fs {
		level := "error"
		if f.Severity != rules.SeverityHigh {
			level = "warning"
		}
		var reg *region
		if f.Line > 0 {
			reg = &region{StartLine: f.Line, StartColumn: f.Column}
		}
		props := map[string]any{"provider": f.Provider, "tool": f.Tool, "masked": f.Masked}
		if f.Record != "" {
			props["record"] = f.Record
		}
		if f.Status != "" {
			props["status"] = f.Status
		}
		results = append(results, result{
			RuleID:  f.RuleID,
			Level:   level,
			Message: message{Text: fmt.Sprintf("%s (%s) found in %s history: %s", f.Provider, f.RuleID, f.ToolName, f.Masked)},
			Locations: []location{{Physical: physical{
				Artifact: artifact{URI: "file://" + f.Path}, Region: reg}}},
			Fingerprints: map[string]string{"agentleaks/v1": f.Fingerprint},
			Properties:   props,
		})
	}
	if rs == nil {
		rs = []rule{}
	}
	doc := log{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{Name: "agentleaks", Version: version,
				InfoURI: "https://github.com/Arthur031221/agentleaks", Rules: rs}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
