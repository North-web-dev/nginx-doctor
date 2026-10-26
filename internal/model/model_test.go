package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCleanStripsControlChars(t *testing.T) {
	in := "evil\x1b[31mHACK\x1b[0m\x07\x00.com"
	got := Clean(in)
	if strings.ContainsAny(got, "\x1b\x07\x00") {
		t.Fatalf("Clean left control chars: %q", got)
	}
	if !strings.Contains(got, "HACK") || !strings.Contains(got, ".com") {
		t.Fatalf("Clean dropped visible text: %q", got)
	}
}

func TestCleanTabsAndNewlines(t *testing.T) {
	got := Clean("a\tb\nc\rd")
	if got != "a b c d" {
		t.Fatalf("got %q", got)
	}
}

func TestSeverityJSON(t *testing.T) {
	b, err := json.Marshal(Fail)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"FAIL"` {
		t.Fatalf("got %s", b)
	}
}

func TestSortFindingsFailFirst(t *testing.T) {
	fs := []Finding{
		{Severity: Warn, Scope: "http", Title: "b"},
		{Severity: Fail, Scope: "http", Title: "a"},
	}
	SortFindings(fs)
	if fs[0].Severity != Fail {
		t.Fatalf("expected FAIL first, got %v", fs[0].Severity)
	}
}
