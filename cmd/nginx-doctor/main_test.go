package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/North-web-dev/nginx-doctor/internal/loader"
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

func TestIncompleteFailsClosed(t *testing.T) {
	old := loader.MaxNodes
	defer func() { loader.MaxNodes = old }()
	loader.MaxNodes = 20

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snippet.conf"),
		[]byte("server { listen 80; server_name a.test; root /srv; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("http {\n")
	for i := 0; i < 300; i++ {
		b.WriteString("  include snippet.conf;\n")
	}
	b.WriteString("}\n")
	top := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(top, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := run([]string{"--no-color", top}, &out, &errb, false)
	if code != 2 {
		t.Fatalf("a truncated analysis must exit 2, got %d", code)
	}
	combined := out.String() + errb.String()
	if !strings.Contains(strings.ToLower(combined), "incomplete") {
		t.Fatalf("output must state the analysis is incomplete, got:\n%s", combined)
	}
}

func runIncomplete(t *testing.T, dir, top string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run([]string{"--no-color", top}, &out, &errb, false)
	return code, out.String() + errb.String()
}

func TestDepthLimitFailsClosed(t *testing.T) {
	dir := t.TempDir()
	// A chain longer than the include-depth limit.
	for i := 0; i < 40; i++ {
		body := "include a" + itoa(i+1) + ".conf;\n"
		if err := os.WriteFile(filepath.Join(dir, "a"+itoa(i)+".conf"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(dir, "a40.conf"), []byte("server { listen 80; }\n"), 0o644)
	top := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(top, []byte("http { include a0.conf; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, combined := runIncomplete(t, dir, top)
	if code != 2 || !strings.Contains(strings.ToLower(combined), "incomplete") {
		t.Fatalf("too-deep include must exit 2 + incomplete; code=%d\n%s", code, combined)
	}
}

func TestOversizeIncludeFailsClosed(t *testing.T) {
	old := loader.MaxFileSize
	defer func() { loader.MaxFileSize = old }()
	loader.MaxFileSize = 128

	dir := t.TempDir()
	big := strings.Repeat("# padding padding padding\n", 50) // > 128 bytes
	if err := os.WriteFile(filepath.Join(dir, "big.conf"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	top := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(top, []byte("http{include big.conf;}\n"), 0o644); err != nil { // < 128 bytes
		t.Fatal(err)
	}
	code, combined := runIncomplete(t, dir, top)
	if code != 2 || !strings.Contains(strings.ToLower(combined), "incomplete") {
		t.Fatalf("oversize include must exit 2 + incomplete; code=%d\n%s", code, combined)
	}
}

func TestUnreadableIncludeFailsClosed(t *testing.T) {
	dir := t.TempDir()
	// A broken symlink the glob matches but cannot be stat'd/read.
	if err := os.Symlink(filepath.Join(dir, "does-not-exist"), filepath.Join(dir, "broken.conf")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	top := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(top, []byte("http { include broken.conf; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, combined := runIncomplete(t, dir, top)
	if code != 2 || !strings.Contains(strings.ToLower(combined), "incomplete") {
		t.Fatalf("unreadable include must exit 2 + incomplete; code=%d\n%s", code, combined)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestHelp(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--help"}, &out, &errb, false)
	if code != 0 || !strings.Contains(out.String(), "usage:") {
		t.Fatalf("help should exit 0 and print usage, got %d", code)
	}
}
