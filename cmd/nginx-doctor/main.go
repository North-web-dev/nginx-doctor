// Command nginx-doctor lints an nginx configuration for security, performance,
// and correctness mistakes and prints the exact fix for each. It is read-only:
// it never edits or reloads nginx.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/North-web-dev/nginx-doctor/internal/loader"
	"github.com/North-web-dev/nginx-doctor/internal/model"
	"github.com/North-web-dev/nginx-doctor/internal/report"
	"github.com/North-web-dev/nginx-doctor/internal/rules"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

const usage = `nginx-doctor %s — lint an nginx config for security, performance and correctness mistakes

usage:
  nginx-doctor [flags] [path]

  path   config file to lint. Default: auto-discover /etc/nginx/nginx.conf.
         Use "-" to read from stdin.

flags:
  --json                     emit findings as JSON
  --severity warn|fail       only show findings at or above this severity
  --only a,b,c               limit to categories: security, perf, correctness
  --no-include               do not resolve include directives
  --allow-external-includes  allow includes that resolve outside the config dir
  --fix-preview              after the report, print a copy-pasteable fix list
  --no-color                 disable ANSI colour
  --version                  print version and exit
  -h, --help                 print this help

exit codes:
  0  no FAIL findings
  1  at least one FAIL finding
  2  parse or usage error

nginx-doctor is read-only. It never edits or reloads your nginx config.
`

type config struct {
	path       string
	json       bool
	severity   model.Severity
	only       map[string]bool
	noInclude  bool
	allowExt   bool
	fixPreview bool
	noColor    bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, isTerminal(os.Stdout)))
}

func run(args []string, stdout, stderr io.Writer, interactive bool) int {
	cfg, showHelp, showVersion, err := parseArgs(args)
	if err != nil {
		errln(stderr, err)
		fmt.Fprintf(stderr, usage, version)
		return 2
	}
	if showHelp {
		fmt.Fprintf(stdout, usage, version)
		return 0
	}
	if showVersion {
		fmt.Fprintf(stdout, "nginx-doctor %s\n", version)
		return 0
	}

	path := cfg.path
	if path == "" {
		p, derr := discover()
		if derr != nil {
			errln(stderr, derr)
			return 2
		}
		path = p
	}

	res, err := loader.Load(path, loader.Options{
		NoInclude:             cfg.noInclude,
		AllowExternalIncludes: cfg.allowExt,
	})
	if err != nil {
		errln(stderr, err)
		return 2
	}

	findings := rules.Analyze(res.Root, rules.Options{Categories: cfg.only})
	rep := report.Build(res.Path, findings, res.Notes)

	if cfg.json {
		if err := rep.WriteJSON(stdout); err != nil {
			errln(stderr, err)
			return 2
		}
	} else {
		color := !cfg.noColor && interactive
		rep.WriteText(stdout, cfg.severity, color)
		if cfg.fixPreview {
			writeFixPreview(stdout, findings)
		}
	}

	return rep.ExitCode()
}

func parseArgs(args []string) (config, bool, bool, error) {
	cfg := config{severity: model.Pass}
	var help, ver bool

	i := 0
	for i < len(args) {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			help = true
		case arg == "--version":
			ver = true
		case arg == "--json":
			cfg.json = true
		case arg == "--no-include":
			cfg.noInclude = true
		case arg == "--allow-external-includes":
			cfg.allowExt = true
		case arg == "--fix-preview":
			cfg.fixPreview = true
		case arg == "--no-color":
			cfg.noColor = true
		case arg == "--severity":
			i++
			if i >= len(args) {
				return cfg, false, false, fmt.Errorf("--severity needs a value (warn or fail)")
			}
			s, err := parseSeverity(args[i])
			if err != nil {
				return cfg, false, false, err
			}
			cfg.severity = s
		case strings.HasPrefix(arg, "--severity="):
			s, err := parseSeverity(strings.TrimPrefix(arg, "--severity="))
			if err != nil {
				return cfg, false, false, err
			}
			cfg.severity = s
		case arg == "--only":
			i++
			if i >= len(args) {
				return cfg, false, false, fmt.Errorf("--only needs a comma-separated category list")
			}
			m, err := parseOnly(args[i])
			if err != nil {
				return cfg, false, false, err
			}
			cfg.only = m
		case strings.HasPrefix(arg, "--only="):
			m, err := parseOnly(strings.TrimPrefix(arg, "--only="))
			if err != nil {
				return cfg, false, false, err
			}
			cfg.only = m
		case arg == "-":
			cfg.path = "-"
		case strings.HasPrefix(arg, "-") && arg != "-":
			return cfg, false, false, fmt.Errorf("unknown flag: %s", arg)
		default:
			if cfg.path != "" {
				return cfg, false, false, fmt.Errorf("unexpected extra argument: %s", arg)
			}
			cfg.path = arg
		}
		i++
	}
	return cfg, help, ver, nil
}

func parseSeverity(v string) (model.Severity, error) {
	switch strings.ToLower(v) {
	case "warn":
		return model.Warn, nil
	case "fail":
		return model.Fail, nil
	case "pass", "all":
		return model.Pass, nil
	default:
		return model.Pass, fmt.Errorf("invalid --severity %q (want warn or fail)", v)
	}
}

func parseOnly(v string) (map[string]bool, error) {
	m := map[string]bool{}
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		switch part {
		case model.CatSecurity, model.CatPerformance, model.CatCorrectness:
			m[part] = true
		case "performance":
			m[model.CatPerformance] = true
		default:
			return nil, fmt.Errorf("invalid --only category %q (want security, perf, correctness)", part)
		}
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("--only had no valid categories")
	}
	return m, nil
}

// discover returns the first existing default config path.
func discover() (string, error) {
	candidates := []string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
		"/usr/local/etc/nginx/nginx.conf",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("no nginx.conf found in default locations; pass a path or use '-' for stdin")
}

func writeFixPreview(w io.Writer, findings []model.Finding) {
	var fixes []string
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Fix == "" || seen[f.Fix] {
			continue
		}
		seen[f.Fix] = true
		fixes = append(fixes, model.Clean(f.Fix))
	}
	if len(fixes) == 0 {
		return
	}
	fmt.Fprintln(w, "\nfix preview (suggested directives — review before applying; nginx-doctor never writes):")
	for _, fx := range fixes {
		fmt.Fprintf(w, "  %s\n", fx)
	}
}

// errln prints an error with control characters stripped, so config-derived
// text in an error message (paths, parser output) cannot inject terminal
// escapes.
func errln(w io.Writer, err error) {
	fmt.Fprintf(w, "error: %s\n", model.Clean(err.Error()))
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
