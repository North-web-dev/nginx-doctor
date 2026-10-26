package rules

import (
	"os"
	"strings"
	"testing"

	"github.com/North-web-dev/nginx-doctor/internal/loader"
	"github.com/North-web-dev/nginx-doctor/internal/model"
)

func analyzeFixture(t *testing.T, path string, opts Options) []model.Finding {
	t.Helper()
	r, err := loader.Load(path, loader.Options{})
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return Analyze(r.Root, opts)
}

func analyzeString(t *testing.T, src string) []model.Finding {
	t.Helper()
	dir := t.TempDir()
	p := dir + "/nginx.conf"
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return analyzeFixture(t, p, Options{})
}

func has(fs []model.Finding, sev model.Severity, cat, substr string) bool {
	for _, f := range fs {
		if f.Severity == sev && f.Category == cat && strings.Contains(f.Title, substr) {
			return true
		}
	}
	return false
}

func hasAny(fs []model.Finding, substr string) bool {
	for _, f := range fs {
		if strings.Contains(f.Title, substr) {
			return true
		}
	}
	return false
}

func TestCleanConfigNoProblems(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/clean/nginx.conf", Options{})
	for _, f := range fs {
		if f.Severity != model.Pass {
			t.Errorf("clean config produced non-PASS: [%s] %s (%s)", f.Severity, f.Title, f.Scope)
		}
	}
}

func TestLegacyTLSFails(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{})
	if !has(fs, model.Fail, model.CatSecurity, "obsolete protocols") {
		t.Fatal("expected FAIL for legacy TLS")
	}
}

func TestWeakCiphersFail(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{})
	if !has(fs, model.Fail, model.CatSecurity, "weak/broken ciphers") {
		t.Fatal("expected FAIL for weak ciphers")
	}
}

func TestDotfileExposureDetected(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{})
	if !has(fs, model.Warn, model.CatSecurity, "dotfile deny rule") {
		t.Fatal("expected dotfile exposure warning")
	}
}

func TestDotfileDenyPasses(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/clean/nginx.conf", Options{})
	if !has(fs, model.Pass, model.CatSecurity, "dotfiles") {
		t.Fatal("expected dotfile PASS on clean config")
	}
}

func TestServerTokensOnWarns(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{})
	if !has(fs, model.Warn, model.CatSecurity, "server_tokens on") {
		t.Fatal("expected server_tokens warning")
	}
}

func TestMissingHeadersWarn(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{})
	if !has(fs, model.Warn, model.CatSecurity, "missing security headers") {
		t.Fatal("expected missing security headers warning")
	}
}

func TestAddHeaderInheritanceReset(t *testing.T) {
	src := `http {
  gzip on; server_tokens off; client_max_body_size 1m;
  add_header Strict-Transport-Security "max-age=1" always;
  server {
    listen 443 ssl;
    ssl_certificate x; ssl_certificate_key y;
    ssl_protocols TLSv1.2;
    root /srv;
    add_header X-Frame-Options SAMEORIGIN;
    location ~ /\. { deny all; }
  }
}`
	fs := analyzeString(t, src)
	if !has(fs, model.Warn, model.CatSecurity, "resets inherited headers") {
		t.Fatalf("expected add_header inheritance reset warning, got %v", titles(fs))
	}
}

func TestIfMisuseDetected(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{})
	if !has(fs, model.Warn, model.CatCorrectness, "if is evil") {
		t.Fatal("expected if-misuse warning")
	}
}

func TestServerNameCollision(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{})
	if !hasAny(fs, "is defined on 2 servers") {
		t.Fatal("expected server_name collision warning")
	}
}

func TestUpstreamKeepaliveMissing(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{})
	if !has(fs, model.Warn, model.CatPerformance, "no keepalive") {
		t.Fatal("expected upstream keepalive warning")
	}
}

func TestProxyPassVariableSSRF(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{})
	if !has(fs, model.Warn, model.CatSecurity, "SSRF") {
		t.Fatal("expected proxy_pass variable SSRF advisory")
	}
}

func TestTLSPassthroughAdvisory(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{})
	if !has(fs, model.Warn, model.CatCorrectness, "SNI/TLS passthrough") {
		t.Fatal("expected TLS passthrough advisory")
	}
}

func TestAutoindexWarn(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{})
	if !has(fs, model.Warn, model.CatSecurity, "autoindex on") {
		t.Fatal("expected autoindex warning")
	}
}

func TestHTTP2Missing(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{})
	if !has(fs, model.Warn, model.CatPerformance, "without HTTP/2") {
		t.Fatal("expected http2 warning")
	}
}

func TestOnlyFilter(t *testing.T) {
	fs := analyzeFixture(t, "../../testdata/bad/nginx.conf", Options{Categories: map[string]bool{model.CatPerformance: true}})
	for _, f := range fs {
		if f.Category != model.CatPerformance {
			t.Fatalf("--only perf leaked a %s finding: %s", f.Category, f.Title)
		}
	}
	if len(fs) == 0 {
		t.Fatal("expected some perf findings")
	}
}

func TestAliasTrailingSlashMismatch(t *testing.T) {
	src := `http {
  gzip on; server_tokens off; client_max_body_size 1m;
  server {
    listen 80;
    location /static/ { alias /var/www/static; }
  }
}`
	fs := analyzeString(t, src)
	if !has(fs, model.Warn, model.CatCorrectness, "alias trailing slash") {
		t.Fatalf("expected alias trailing-slash warning, got %v", titles(fs))
	}
}

func titles(fs []model.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Title)
	}
	return out
}
