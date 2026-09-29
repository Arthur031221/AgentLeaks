// Package rules loads the detection rule set and matches secrets in text.
//
// Rules live in rules.toml, embedded at build time. Each rule has an id, a
// provider, a regular expression, optional keyword prefilters, an optional
// entropy floor, and an optional allowlist. Rules are ordered: when two rules
// match overlapping bytes, the earlier rule wins. Specific provider rules
// therefore come before generic assignment rules.
package rules

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed rules.toml
var defaultTOML []byte

// Severity levels used by rules.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
)

// Rule is one compiled detection rule.
type Rule struct {
	ID          string
	Provider    string
	Description string
	Severity    string
	Verify      string
	Regex       *regexp.Regexp
	Group       int
	Entropy     float64
	Keywords    []string
	Allowlist   []*regexp.Regexp
	BlockEnd    *regexp.Regexp
	index       int
	caseInsens  bool
}

// IsBlock reports whether the rule opens a multi-line block (private keys).
func (r *Rule) IsBlock() bool { return r.BlockEnd != nil }

type tomlRule struct {
	ID          string   `toml:"id"`
	Provider    string   `toml:"provider"`
	Description string   `toml:"description"`
	Severity    string   `toml:"severity"`
	Verify      string   `toml:"verify"`
	Regex       string   `toml:"regex"`
	Group       int      `toml:"group"`
	Entropy     float64  `toml:"entropy"`
	Keywords    []string `toml:"keywords"`
	Allowlist   []string `toml:"allowlist"`
	BlockEnd    string   `toml:"block_end"`
}

type tomlFile struct {
	Version int        `toml:"version"`
	Rules   []tomlRule `toml:"rules"`
}

// Set is a compiled, ordered collection of rules with a keyword prefilter.
type Set struct {
	Rules   []*Rule
	byID    map[string]*Rule
	ac      *matcher
	acRules [][]int // keyword index -> rule indexes
	always  []int   // rules with no keywords, always tried
}

// Load parses the embedded default rule set.
func Load() (*Set, error) { return Parse(defaultTOML) }

// MustLoad is Load for callers that treat a broken embedded rule set as fatal.
func MustLoad() *Set {
	s, err := Load()
	if err != nil {
		panic(err)
	}
	return s
}

// Parse compiles a rule set from TOML bytes.
func Parse(data []byte) (*Set, error) {
	var f tomlFile
	if err := toml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("rules: parse toml: %w", err)
	}
	if len(f.Rules) == 0 {
		return nil, fmt.Errorf("rules: no rules defined")
	}
	s := &Set{byID: map[string]*Rule{}}
	var keywords []string
	for i, tr := range f.Rules {
		if tr.ID == "" {
			return nil, fmt.Errorf("rules: rule %d has no id", i)
		}
		if _, dup := s.byID[tr.ID]; dup {
			return nil, fmt.Errorf("rules: duplicate id %q", tr.ID)
		}
		if tr.Regex == "" {
			return nil, fmt.Errorf("rules: %s has no regex", tr.ID)
		}
		re, err := regexp.Compile(tr.Regex)
		if err != nil {
			return nil, fmt.Errorf("rules: %s: %w", tr.ID, err)
		}
		if tr.Group < 0 || tr.Group > re.NumSubexp() {
			return nil, fmt.Errorf("rules: %s: group %d out of range", tr.ID, tr.Group)
		}
		r := &Rule{
			ID:          tr.ID,
			Provider:    tr.Provider,
			Description: tr.Description,
			Severity:    tr.Severity,
			Verify:      tr.Verify,
			Regex:       re,
			Group:       tr.Group,
			Entropy:     tr.Entropy,
			Keywords:    tr.Keywords,
			index:       i,
		}
		if r.Severity == "" {
			r.Severity = SeverityHigh
		}
		switch r.Severity {
		case SeverityHigh, SeverityMedium, SeverityLow:
		default:
			return nil, fmt.Errorf("rules: %s: unknown severity %q", tr.ID, tr.Severity)
		}
		for _, a := range tr.Allowlist {
			are, err := regexp.Compile(a)
			if err != nil {
				return nil, fmt.Errorf("rules: %s allowlist: %w", tr.ID, err)
			}
			r.Allowlist = append(r.Allowlist, are)
		}
		if tr.BlockEnd != "" {
			bre, err := regexp.Compile(tr.BlockEnd)
			if err != nil {
				return nil, fmt.Errorf("rules: %s block_end: %w", tr.ID, err)
			}
			r.BlockEnd = bre
		}
		s.Rules = append(s.Rules, r)
		s.byID[r.ID] = r
		if len(r.Keywords) == 0 {
			s.always = append(s.always, i)
			continue
		}
		for _, k := range r.Keywords {
			k = strings.ToLower(k)
			idx := -1
			for j, existing := range keywords {
				if existing == k {
					idx = j
					break
				}
			}
			if idx == -1 {
				keywords = append(keywords, k)
				s.acRules = append(s.acRules, nil)
				idx = len(keywords) - 1
			}
			s.acRules[idx] = append(s.acRules[idx], i)
		}
	}
	s.ac = newMatcher(keywords)
	return s, nil
}

// Get returns the rule with the given id, or nil.
func (s *Set) Get(id string) *Rule { return s.byID[id] }

// Match is one secret found in a piece of text.
type Match struct {
	Rule   *Rule
	Start  int // byte offset of the secret in the scanned text
	End    int
	Secret string
}

// Scan finds secrets in one line or chunk of text. The keyword prefilter
// runs first, so most lines never touch a regular expression.
func (s *Set) Scan(text []byte) []Match {
	if len(text) == 0 {
		return nil
	}
	candidates := s.candidates(text)
	if len(candidates) == 0 {
		return nil
	}
	var out []Match
	for _, ri := range candidates {
		r := s.Rules[ri]
		locs := r.Regex.FindAllSubmatchIndex(text, -1)
		for _, loc := range locs {
			gs, ge := loc[2*r.Group], loc[2*r.Group+1]
			if gs < 0 || ge <= gs {
				continue
			}
			secret := string(text[gs:ge])
			if r.rejected(secret) {
				continue
			}
			if overlaps(out, gs, ge) {
				continue
			}
			out = append(out, Match{Rule: r, Start: gs, End: ge, Secret: secret})
		}
	}
	sortMatches(out)
	return out
}

// sortMatches orders matches by byte offset so callers see them in the
// order they appear in the text. Overlap resolution already happened.
func sortMatches(ms []Match) {
	for i := 1; i < len(ms); i++ {
		for j := i; j > 0 && ms[j-1].Start > ms[j].Start; j-- {
			ms[j-1], ms[j] = ms[j], ms[j-1]
		}
	}
}

// candidates returns rule indexes to try, in rule order.
func (s *Set) candidates(text []byte) []int {
	hits := s.ac.find(text)
	if len(hits) == 0 && len(s.always) == 0 {
		return nil
	}
	seen := make(map[int]bool, 8)
	var list []int
	for _, ri := range s.always {
		if !seen[ri] {
			seen[ri] = true
			list = append(list, ri)
		}
	}
	for _, k := range hits {
		for _, ri := range s.acRules[k] {
			if !seen[ri] {
				seen[ri] = true
				list = append(list, ri)
			}
		}
	}
	sortInts(list)
	return list
}

func (r *Rule) rejected(secret string) bool {
	if r.Entropy > 0 && Entropy(secret) < r.Entropy {
		return true
	}
	for _, a := range r.Allowlist {
		if a.MatchString(secret) {
			return true
		}
	}
	return false
}

func overlaps(ms []Match, start, end int) bool {
	for _, m := range ms {
		if start < m.End && m.Start < end {
			return true
		}
	}
	return false
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

// Mask returns a preview of a secret that keeps a short prefix and suffix.
func Mask(secret string) string {
	n := len(secret)
	switch {
	case n <= 6:
		return strings.Repeat("*", n)
	case n <= 12:
		return secret[:3] + "..." + secret[n-1:]
	default:
		return secret[:6] + "..." + secret[n-2:]
	}
}

// Fingerprint returns a short stable identifier for a secret value.
func Fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:6])
}

// Redaction returns the replacement text written in place of a secret.
func Redaction(ruleID string) string {
	return "[REDACTED:" + ruleID + "]"
}

// RedactionPattern matches text previously written by Redaction.
var RedactionPattern = regexp.MustCompile(`\[REDACTED:[a-z0-9-]+\]`)
