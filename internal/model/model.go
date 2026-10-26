// Package model holds the normalized config tree and finding types shared
// across the loader, rule, and report packages.
package model

import (
	"sort"
	"strings"
	"unicode"
)

// Node is one directive in the normalized nginx config tree. Include
// directives are expanded in place by the loader, so the tree a Node belongs
// to never contains an "include" node.
type Node struct {
	Name     string
	Args     []string
	Children []*Node
	File     string
	Line     int
	Parent   *Node
}

// Dir returns the direct child directives with the given name.
func (n *Node) Dir(name string) []*Node {
	var out []*Node
	for _, c := range n.Children {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

// Dirs returns every descendant directive with the given name.
func (n *Node) Dirs(name string) []*Node {
	var out []*Node
	for _, c := range n.Children {
		if c.Name == name {
			out = append(out, c)
		}
		out = append(out, c.Dirs(name)...)
	}
	return out
}

// ArgStr joins the directive arguments with single spaces.
func (n *Node) ArgStr() string { return strings.Join(n.Args, " ") }

// HasArg reports whether any argument equals v (case-insensitive).
func (n *Node) HasArg(v string) bool {
	for _, a := range n.Args {
		if strings.EqualFold(a, v) {
			return true
		}
	}
	return false
}

// DisplayLine returns the directive's own line, or for a block the earliest
// line among its children (gonginx reports a block's line at its closing
// brace, which reads worse in a report).
func (n *Node) DisplayLine() int {
	if len(n.Children) == 0 {
		return n.Line
	}
	min := n.Line
	for _, c := range n.Children {
		if c.Line > 0 && (min <= 0 || c.Line < min) {
			min = c.Line
		}
	}
	return min
}

// Severity grades a finding.
type Severity int

const (
	Pass Severity = iota
	Warn
	Fail
)

func (s Severity) String() string {
	switch s {
	case Fail:
		return "FAIL"
	case Warn:
		return "WARN"
	default:
		return "PASS"
	}
}

// MarshalJSON renders the severity as its uppercase name.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// Category labels a finding's concern area.
const (
	CatSecurity    = "security"
	CatPerformance = "perf"
	CatCorrectness = "correctness"
)

// Finding is a single graded observation about the config.
type Finding struct {
	Severity Severity `json:"severity"`
	Category string   `json:"category"`
	Scope    string   `json:"scope"`
	Title    string   `json:"title"`
	Fix      string   `json:"fix"`
	File     string   `json:"file,omitempty"`
	Line     int      `json:"line,omitempty"`
	// Advisory marks a finding that relies on inferred runtime intent static
	// analysis cannot confirm.
	Advisory bool `json:"advisory,omitempty"`
}

// Clean strips control characters (including terminal escape sequences) from a
// config-derived string so untrusted config cannot inject escapes into the
// report. Tabs become spaces; other control runes are dropped.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r == '\n' || r == '\r' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// SortFindings orders findings for stable output: by scope, then severity
// (FAIL first), then category, then title.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Title < b.Title
	})
}
