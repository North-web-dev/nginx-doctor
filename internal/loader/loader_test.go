package loader

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/North-web-dev/nginx-doctor/internal/model"
)

func names(nodes []*model.Node) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.Name)
	}
	return out
}

func httpOf(t *testing.T, r *Result) *model.Node {
	t.Helper()
	for _, n := range r.Root.Children {
		if n.Name == "http" {
			return n
		}
	}
	t.Fatal("no http block")
	return nil
}

func TestIncludeResolution(t *testing.T) {
	r, err := Load("../../testdata/include/nginx.conf", Options{})
	if err != nil {
		t.Fatal(err)
	}
	h := httpOf(t, r)
	servers := h.Dir("server")
	if len(servers) != 1 {
		t.Fatalf("expected 1 server spliced from include, got %d (%v)", len(servers), names(h.Children))
	}
	if got := servers[0].File; !strings.Contains(got, "site.conf") {
		t.Fatalf("included server should keep its own file, got %q", got)
	}
	var foundMissingNote bool
	for _, n := range r.Notes {
		if strings.Contains(n, "missing/*.conf") && strings.Contains(n, "matched no files") {
			foundMissingNote = true
		}
	}
	if !foundMissingNote {
		t.Fatalf("expected honest note about unreadable glob, notes=%v", r.Notes)
	}
}

func TestNoIncludeDisables(t *testing.T) {
	r, err := Load("../../testdata/include/nginx.conf", Options{NoInclude: true})
	if err != nil {
		t.Fatal(err)
	}
	h := httpOf(t, r)
	if len(h.Dir("server")) != 0 {
		t.Fatal("expected no servers with --no-include")
	}
}

func TestIncludeLoopTerminates(t *testing.T) {
	// If cycle detection failed, Load would recurse until the stack blows;
	// the test completing at all proves termination.
	r, err := Load("../../testdata/loop/a.conf", Options{})
	if err != nil {
		t.Fatal(err)
	}
	var cycle bool
	for _, n := range r.Notes {
		if strings.Contains(n, "include cycle") {
			cycle = true
		}
	}
	if !cycle {
		t.Fatalf("expected an include-cycle note, got %v", r.Notes)
	}
}

func TestExternalIncludeSandboxed(t *testing.T) {
	r, err := Load("../../testdata/external/nginx.conf", Options{})
	if err != nil {
		t.Fatal(err)
	}
	h := httpOf(t, r)
	if len(h.Dir("server")) != 0 {
		t.Fatal("external include should be skipped by default")
	}
	var skipped bool
	for _, n := range r.Notes {
		if strings.Contains(n, "outside config directory") {
			skipped = true
		}
	}
	if !skipped {
		t.Fatalf("expected sandbox skip note, got %v", r.Notes)
	}
}

func TestExternalIncludeAllowed(t *testing.T) {
	r, err := Load("../../testdata/external/nginx.conf", Options{AllowExternalIncludes: true})
	if err != nil {
		t.Fatal(err)
	}
	h := httpOf(t, r)
	if len(h.Dir("server")) == 0 {
		t.Fatal("with --allow-external-includes the external file should resolve")
	}
}

func TestMissingTopFileIsError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.conf"), Options{}); err == nil {
		t.Fatal("expected error for missing top config")
	}
}

func TestIncludedFileReadOnce(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snippet.conf"),
		[]byte("server { listen 80; server_name a.test; root /srv; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("http {\n")
	for i := 0; i < 50; i++ {
		b.WriteString("  include snippet.conf;\n")
	}
	b.WriteString("}\n")
	top := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(top, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := Load(top, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// top file + the one unique snippet = 2 reads, even though included 50x.
	if r.FilesRead != 2 {
		t.Fatalf("expected 2 files read (top + one cached snippet), got %d", r.FilesRead)
	}
	h := httpOf(t, r)
	if got := len(h.Dir("server")); got != 50 {
		t.Fatalf("expected 50 spliced servers, got %d", got)
	}
}

func TestTotalByteBudget(t *testing.T) {
	old := MaxTotalBytes
	defer func() { MaxTotalBytes = old }()
	MaxTotalBytes = 4096 // tiny budget

	dir := t.TempDir()
	payload := "server { listen 80; server_name b.test; }\n" + strings.Repeat("# pad\n", 400)
	for _, n := range []string{"a.conf", "b.conf", "c.conf"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(payload), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	top := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(top, []byte("http {\n include a.conf;\n include b.conf;\n include c.conf;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := Load(top, Options{})
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("hitting the byte budget must fail closed with ErrIncomplete, got %v", err)
	}
	if r == nil || !r.Incomplete {
		t.Fatal("expected a partial result flagged Incomplete")
	}
	var budgetNote bool
	for _, n := range r.Notes {
		if strings.Contains(n, "total read budget") {
			budgetNote = true
		}
	}
	if !budgetNote {
		t.Fatalf("expected a total-read-budget note, got %v", r.Notes)
	}
}

func countNodes(n *model.Node) int {
	total := 0
	for _, c := range n.Children {
		total += 1 + countNodes(c)
	}
	return total
}

func TestExpansionBudgetBoundsCachedSplices(t *testing.T) {
	old := MaxNodes
	defer func() { MaxNodes = old }()
	MaxNodes = 200 // tiny expansion budget

	dir := t.TempDir()
	// A small cached file: 10 directives. Reads once, but splicing it 500
	// times would materialize ~5000 nodes without a splice-charged budget.
	if err := os.WriteFile(filepath.Join(dir, "snippet.conf"),
		[]byte(strings.Repeat("map_hash_bucket_size 128;\n", 10)), 0o644); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("http {\n")
	for i := 0; i < 500; i++ {
		b.WriteString("  include snippet.conf;\n")
	}
	b.WriteString("}\n")
	top := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(top, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := Load(top, Options{})
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("blowing the node budget must fail closed with ErrIncomplete, got %v", err)
	}
	if r == nil || !r.Incomplete {
		t.Fatal("expected a partial result flagged Incomplete")
	}
	if r.FilesRead != 2 {
		t.Fatalf("expected file read once (top + snippet), got %d", r.FilesRead)
	}
	nodes := countNodes(r.Root)
	if nodes > MaxNodes+50 {
		t.Fatalf("expansion not bounded: %d nodes materialized (budget %d)", nodes, MaxNodes)
	}
}

func TestExpandIncludeChargesPerMatchedFile(t *testing.T) {
	old := MaxNodes
	defer func() { MaxNodes = old }()
	// Budget below the number of matched files: each matched file must be
	// charged even though the snippets create no new nodes once we stop, so
	// a glob matching many files cannot run unbounded.
	MaxNodes = 5

	dir := t.TempDir()
	cd := filepath.Join(dir, "conf.d")
	if err := os.Mkdir(cd, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		name := filepath.Join(cd, fmtName(i))
		if err := os.WriteFile(name, []byte("server { listen 80; }\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	top := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(top, []byte("http {\n include conf.d/*.conf;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := Load(top, Options{})
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("expected ErrIncomplete once the budget is hit mid-glob, got %v", err)
	}
	// Far fewer than 100 files should have been read before the budget tripped.
	if r.FilesRead > 20 {
		t.Fatalf("expected the glob to stop early, read %d files", r.FilesRead)
	}
}

func fmtName(i int) string {
	return "s" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + ".conf"
}

func TestFileSizeCap(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.conf")
	// one directive plus padding past the cap
	data := []byte("http {}\n")
	pad := make([]byte, maxFileSize+10)
	for i := range pad {
		pad[i] = ' '
	}
	if err := os.WriteFile(big, append(data, pad...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(big, Options{}); err == nil {
		t.Fatal("expected size-cap error")
	}
}
