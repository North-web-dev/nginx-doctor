// Package report groups findings, renders the text and JSON output, and
// computes the summary grade and exit code. Every config-derived string is run
// through model.Clean here, the single output boundary, so a hostile config
// cannot inject terminal escapes into the report.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/North-web-dev/nginx-doctor/internal/model"
)

// Summary counts findings and holds the computed grade.
type Summary struct {
	Fail  int    `json:"fail"`
	Warn  int    `json:"warn"`
	Pass  int    `json:"pass"`
	Score int    `json:"score"`
	Grade string `json:"grade"`
}

// Report is the full result for one analyzed config.
type Report struct {
	Path string `json:"path"`
	// Incomplete is true when the loader could not fully resolve the config
	// (a resource limit was hit). The findings are then partial and must not
	// be read as a clean result.
	Incomplete bool            `json:"incomplete"`
	Findings   []model.Finding `json:"findings"`
	Notes      []string        `json:"notes,omitempty"`
	Summary    Summary         `json:"summary"`
}

// Build assembles a report from findings and loader notes. incomplete marks a
// run where resource limits stopped include resolution early.
func Build(path string, findings []model.Finding, notes []string, incomplete bool) Report {
	var s Summary
	for _, f := range findings {
		switch f.Severity {
		case model.Fail:
			s.Fail++
		case model.Warn:
			s.Warn++
		case model.Pass:
			s.Pass++
		}
	}
	s.Score = grade(s.Fail, s.Warn)
	s.Grade = letter(s.Score)

	clean := make([]string, len(notes))
	for i, n := range notes {
		clean[i] = model.Clean(n)
	}
	return Report{Path: model.Clean(path), Incomplete: incomplete, Findings: findings, Notes: clean, Summary: s}
}

func grade(fail, warn int) int {
	score := 100 - fail*25 - warn*5
	if score < 0 {
		score = 0
	}
	return score
}

func letter(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// ExitCode returns 1 when any FAIL is present, else 0.
func (r Report) ExitCode() int {
	if r.Summary.Fail > 0 {
		return 1
	}
	return 0
}

// WriteJSON renders the report as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	// Findings themselves may carry config-derived text; clean on the way out.
	out := r
	out.Findings = cleanFindings(r.Findings)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

func cleanFindings(in []model.Finding) []model.Finding {
	out := make([]model.Finding, len(in))
	for i, f := range in {
		f.Scope = model.Clean(f.Scope)
		f.Title = model.Clean(f.Title)
		f.Fix = model.Clean(f.Fix)
		f.File = model.Clean(f.File)
		out[i] = f
	}
	return out
}

// WriteText renders the grouped human report. threshold hides findings below
// the given severity; color toggles ANSI coloring.
func (r Report) WriteText(w io.Writer, threshold model.Severity, color bool) {
	fmt.Fprintf(w, "nginx-doctor — %s\n", r.Path)

	if r.Incomplete {
		fmt.Fprintln(w, "\n*** ANALYSIS INCOMPLETE: include resolution hit a resource limit; the")
		fmt.Fprintln(w, "*** findings below are PARTIAL and must not be read as a clean result. ***")
	}

	if len(r.Notes) > 0 {
		fmt.Fprintln(w, "\nconfig loading")
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  note  %s\n", n)
		}
	}

	shown := cleanFindings(r.Findings)
	groups, order := groupByScope(shown, threshold)

	if len(order) == 0 {
		fmt.Fprintln(w, "\nno findings at or above the selected severity.")
	}
	for _, scope := range order {
		fmt.Fprintf(w, "\n%s\n", scope)
		for _, f := range groups[scope] {
			tag := f.Severity.String()
			if color {
				tag = colorize(f.Severity, tag)
			}
			adv := ""
			if f.Advisory {
				adv = " (advisory)"
			}
			loc := ""
			if f.File != "" && f.Line > 0 {
				loc = fmt.Sprintf("  [%s:%d]", f.File, f.Line)
			}
			fmt.Fprintf(w, "  %s  [%s]%s %s%s\n", tag, f.Category, adv, f.Title, loc)
			if f.Fix != "" {
				fmt.Fprintf(w, "        fix: %s\n", f.Fix)
			}
		}
	}

	s := r.Summary
	fmt.Fprintf(w, "\nsummary: %d FAIL, %d WARN, %d PASS  —  score %d/100, grade %s\n",
		s.Fail, s.Warn, s.Pass, s.Score, s.Grade)
	if r.Incomplete {
		fmt.Fprintln(w, "status: INCOMPLETE — analysis did not finish; treat results as unreliable")
	}
}

func groupByScope(fs []model.Finding, threshold model.Severity) (map[string][]model.Finding, []string) {
	groups := map[string][]model.Finding{}
	for _, f := range fs {
		if f.Severity < threshold {
			continue
		}
		groups[f.Scope] = append(groups[f.Scope], f)
	}
	order := make([]string, 0, len(groups))
	for k := range groups {
		order = append(order, k)
	}
	sort.Slice(order, func(i, j int) bool {
		return scopeRank(order[i]) < scopeRank(order[j])
	})
	return groups, order
}

// scopeRank orders global/http/events/upstream ahead of server blocks, then
// alphabetically, so the report reads top-down.
func scopeRank(s string) string {
	switch {
	case s == "global":
		return "0"
	case s == "http":
		return "1"
	case s == "events":
		return "2"
	case strings.HasPrefix(s, "upstream "):
		return "3" + s
	default:
		return "4" + s
	}
}

func colorize(sev model.Severity, s string) string {
	switch sev {
	case model.Fail:
		return "\x1b[31m" + s + "\x1b[0m"
	case model.Warn:
		return "\x1b[33m" + s + "\x1b[0m"
	default:
		return "\x1b[32m" + s + "\x1b[0m"
	}
}
