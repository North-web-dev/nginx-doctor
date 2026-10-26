package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestExitCleanIsZero(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--no-color", "../../testdata/clean/nginx.conf"}, &out, &errb, false)
	if code != 0 {
		t.Fatalf("clean config should exit 0, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "grade A") {
		t.Fatalf("expected grade A, got:\n%s", out.String())
	}
}

func TestExitBadIsOne(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--no-color", "../../testdata/bad/nginx.conf"}, &out, &errb, false)
	if code != 1 {
		t.Fatalf("bad config with FAIL should exit 1, got %d", code)
	}
}

func TestMissingPathIsTwo(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"/nonexistent/does/not/exist.conf"}, &out, &errb, false)
	if code != 2 {
		t.Fatalf("missing path should exit 2, got %d", code)
	}
}

func TestUnknownFlagIsTwo(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--bogus"}, &out, &errb, false)
	if code != 2 {
		t.Fatalf("unknown flag should exit 2, got %d", code)
	}
}

func TestBadSeverityValueIsTwo(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--severity", "nope", "../../testdata/clean/nginx.conf"}, &out, &errb, false)
	if code != 2 {
		t.Fatalf("invalid --severity should exit 2, got %d", code)
	}
}

func TestStdin(t *testing.T) {
	// run reads os.Stdin for "-"; here we only assert flag plumbing via a file.
	var out, errb bytes.Buffer
	code := run([]string{"--no-color", "--json", "../../testdata/bad/nginx.conf"}, &out, &errb, false)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(out.String(), `"grade"`) {
		t.Fatalf("expected JSON output, got:\n%s", out.String())
	}
}

func TestOnlyAndSeverityParse(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--no-color", "--only", "perf", "--severity", "warn", "../../testdata/bad/nginx.conf"}, &out, &errb, false)
	// perf category has no FAIL in the bad fixture, so exit should be 0.
	if code != 0 {
		t.Fatalf("perf-only should exit 0 (no perf FAILs), got %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "[security]") {
		t.Fatal("--only perf leaked a security finding")
	}
}

func TestErrorOutputSanitized(t *testing.T) {
	var out, errb bytes.Buffer
	// A path carrying an ESC byte reaches the error message; it must be
	// stripped before printing to stderr.
	code := run([]string{"/nonexistent\x1b[31mHACK.conf"}, &out, &errb, false)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if bytes.ContainsRune(errb.Bytes(), 0x1b) {
		t.Fatalf("error output contains ESC byte: %q", errb.String())
	}
}

func TestHelp(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--help"}, &out, &errb, false)
	if code != 0 || !strings.Contains(out.String(), "usage:") {
		t.Fatalf("help should exit 0 and print usage, got %d", code)
	}
}
