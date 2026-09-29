package rules

import (
	"sort"
	"testing"
)

func findSorted(m *matcher, text string) []int {
	hits := m.find([]byte(text))
	sort.Ints(hits)
	return hits
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMatcherFindsKeywords(t *testing.T) {
	m := newMatcher([]string{"sk-", "ghp_", "private key", "hooks.slack.com"})
	cases := []struct {
		text string
		want []int
	}{
		{"nothing here", nil},
		{"token ghp_abc", []int{1}},
		{"sk-something and ghp_ too", []int{0, 1}},
		{"-----BEGIN RSA PRIVATE KEY-----", []int{2}},
		{"url https://hooks.slack.com/services/x", []int{3}},
	}
	for _, c := range cases {
		got := findSorted(m, c.text)
		if !equalInts(got, c.want) {
			t.Errorf("find(%q) = %v, want %v", c.text, got, c.want)
		}
	}
}

func TestMatcherCaseInsensitive(t *testing.T) {
	m := newMatcher([]string{"sk-", "Private Key", "AKIA"})
	for _, text := range []string{"SK-abc", "sK-abc", "sk-abc"} {
		if got := findSorted(m, text); !equalInts(got, []int{0}) {
			t.Errorf("find(%q) = %v, want [0]", text, got)
		}
	}
	if got := findSorted(m, "the PRIVATE KEY block"); !equalInts(got, []int{1}) {
		t.Errorf("uppercase keyword: got %v", got)
	}
	if got := findSorted(m, "akiaxyz"); !equalInts(got, []int{2}) {
		t.Errorf("lowercase text against uppercase keyword: got %v", got)
	}
}

func TestMatcherOverlappingKeywords(t *testing.T) {
	m := newMatcher([]string{"sk-", "sk-ant-", "ant-", "sk-proj-"})
	got := findSorted(m, "key sk-ant-api03-x")
	if !equalInts(got, []int{0, 1, 2}) {
		t.Errorf("overlapping keywords: got %v, want [0 1 2]", got)
	}
	got = findSorted(m, "sk-proj-abc")
	if !equalInts(got, []int{0, 3}) {
		t.Errorf("prefix keyword: got %v, want [0 3]", got)
	}
}

func TestMatcherEdges(t *testing.T) {
	m := newMatcher([]string{"abc", "xyz"})
	if got := m.find(nil); got != nil {
		t.Errorf("empty text: got %v", got)
	}
	if got := findSorted(m, "abc"); !equalInts(got, []int{0}) {
		t.Errorf("keyword equals text: got %v", got)
	}
	if got := findSorted(m, "abc at start"); !equalInts(got, []int{0}) {
		t.Errorf("keyword at start: got %v", got)
	}
	if got := findSorted(m, "ends with xyz"); !equalInts(got, []int{1}) {
		t.Errorf("keyword at end: got %v", got)
	}
	if got := findSorted(m, "abcabcxyz"); !equalInts(got, []int{0, 1}) {
		t.Errorf("repeated keywords deduplicate: got %v", got)
	}
	empty := newMatcher(nil)
	if got := empty.find([]byte("anything")); got != nil {
		t.Errorf("matcher without keywords: got %v", got)
	}
}

func TestEntropy(t *testing.T) {
	if got := Entropy(""); got != 0 {
		t.Errorf("empty entropy = %v", got)
	}
	if got := Entropy("aaaaaaaaaaaaaaaa"); got != 0 {
		t.Errorf("single symbol entropy = %v, want 0", got)
	}
	low := Entropy("abababababababab")
	if low < 0.99 || low > 1.01 {
		t.Errorf("two symbol entropy = %v, want 1", low)
	}
	high := Entropy(gen(alnumSet, 64, 99))
	if high < 4.5 {
		t.Errorf("random alnum entropy = %v, want at least 4.5", high)
	}
	if Entropy("0123456789") < Entropy("0011223344") {
		t.Errorf("entropy should reward more distinct symbols")
	}
}
