package rules

import "math"

// matcher is a small case-insensitive Aho-Corasick automaton over bytes.
// It answers "which keywords occur in this text" in one pass, which is what
// lets the scanner skip regular expressions on the vast majority of lines.
type matcher struct {
	goto_  [][256]int32
	fail   []int32
	output [][]int
}

var lowerTable = func() [256]byte {
	var t [256]byte
	for i := 0; i < 256; i++ {
		c := byte(i)
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		t[i] = c
	}
	return t
}()

func newMatcher(keywords []string) *matcher {
	m := &matcher{}
	m.addState()
	for i, kw := range keywords {
		cur := int32(0)
		for j := 0; j < len(kw); j++ {
			c := lowerTable[kw[j]]
			next := m.goto_[cur][c]
			if next == 0 {
				next = int32(m.addState())
				m.goto_[cur][c] = next
			}
			cur = next
		}
		m.output[cur] = append(m.output[cur], i)
	}
	// Breadth-first construction of failure links.
	queue := make([]int32, 0, len(m.goto_))
	for c := 0; c < 256; c++ {
		if next := m.goto_[0][c]; next != 0 {
			m.fail[next] = 0
			queue = append(queue, next)
		}
	}
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		for c := 0; c < 256; c++ {
			next := m.goto_[state][c]
			if next == 0 {
				continue
			}
			queue = append(queue, next)
			f := m.fail[state]
			for f != 0 && m.goto_[f][c] == 0 {
				f = m.fail[f]
			}
			m.fail[next] = m.goto_[f][c]
			if m.fail[next] == next {
				m.fail[next] = 0
			}
			m.output[next] = append(m.output[next], m.output[m.fail[next]]...)
		}
	}
	return m
}

func (m *matcher) addState() int {
	m.goto_ = append(m.goto_, [256]int32{})
	m.fail = append(m.fail, 0)
	m.output = append(m.output, nil)
	return len(m.goto_) - 1
}

// find returns the distinct keyword indexes present in text.
func (m *matcher) find(text []byte) []int {
	if len(m.goto_) <= 1 {
		return nil
	}
	var hits []int
	var seen map[int]bool
	state := int32(0)
	for i := 0; i < len(text); i++ {
		c := lowerTable[text[i]]
		for state != 0 && m.goto_[state][c] == 0 {
			state = m.fail[state]
		}
		state = m.goto_[state][c]
		if out := m.output[state]; len(out) > 0 {
			if seen == nil {
				seen = make(map[int]bool, 4)
			}
			for _, k := range out {
				if !seen[k] {
					seen[k] = true
					hits = append(hits, k)
				}
			}
		}
	}
	return hits
}

// Entropy returns the Shannon entropy of s in bits per byte.
func Entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
