package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/North-web-dev/nginx-doctor/internal/model"
)

func TestGradeAndExit(t *testing.T) {
	r := Build("x", []model.Finding{
		{Severity: model.Fail, Category: model.CatSecurity, Scope: "http", Title: "boom"},
	}, nil)
	if r.Summary.Grade == "A" {
		t.Fatal("a FAIL should not grade A")
	}
	if r.ExitCode() != 1 {
		t.Fatalf("expected exit 1, got %d", r.ExitCode())
	}

	clean := Build("x", []model.Finding{{Severity: model.Pass, Scope: "http", Title: "ok"}}, nil)
	if clean.Summary.Grade != "A" || clean.ExitCode() != 0 {
		t.Fatalf("clean should be A/0, got %s/%d", clean.Summary.Grade, clean.ExitCode())
	}
}

func TestTextOutputSanitized(t *testing.T) {
	r := Build("conf\x1b[31m", []model.Finding{
		{Severity: model.Fail, Category: model.CatSecurity, Scope: "server evil\x1b[31mX", Title: "bad \x1b[0mthing", Fix: "fix\x1b[1m"},
	}, []string{"note\x1b[2m"})
	var buf bytes.Buffer
	r.WriteText(&buf, model.Pass, false)
	if bytes.ContainsRune(buf.Bytes(), 0x1b) {
		t.Fatalf("text output contains ESC byte: %q", buf.String())
	}
}

func TestJSONOutputSanitized(t *testing.T) {
	r := Build("x", []model.Finding{
		{Severity: model.Warn, Category: model.CatSecurity, Scope: "s\x1b[31m", Title: "t\x1b[0m", Fix: "f\x07"},
	}, nil)
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(buf.Bytes(), "\x1b\x07") {
		t.Fatalf("json output contains control bytes: %q", buf.String())
	}
	if !strings.Contains(buf.String(), `"WARN"`) {
		t.Fatalf("json severity should render as a name, got %s", buf.String())
	}
}

func TestSeverityThresholdHidesLower(t *testing.T) {
	r := Build("x", []model.Finding{
		{Severity: model.Warn, Category: model.CatSecurity, Scope: "http", Title: "warnone"},
		{Severity: model.Fail, Category: model.CatSecurity, Scope: "http", Title: "failone"},
	}, nil)
	var buf bytes.Buffer
	r.WriteText(&buf, model.Fail, false)
	out := buf.String()
	if strings.Contains(out, "warnone") {
		t.Fatal("--severity fail should hide WARN findings")
	}
	if !strings.Contains(out, "failone") {
		t.Fatal("--severity fail should show FAIL findings")
	}
}
