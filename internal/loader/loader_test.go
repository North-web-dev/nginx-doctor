package loader

import (
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
