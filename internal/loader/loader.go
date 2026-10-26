// Package loader reads an nginx config, parses it with gonginx, and resolves
// include directives into a single normalized model.Node tree. Include
// resolution is sandboxed to the config directory and bounded in size, depth,
// and cycle length so a hostile config cannot make the linter read arbitrary
// files or loop forever.
package loader

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/North-web-dev/nginx-doctor/internal/model"
	"github.com/tufanbarisyildirim/gonginx/config"
	"github.com/tufanbarisyildirim/gonginx/parser"
)

// Limits bound include resolution.
const (
	maxFileSize     = 16 << 20 // 16 MiB per file
	maxIncludeDepth = 32
	maxTotalFiles   = 2000
)

// Options controls how a config is loaded.
type Options struct {
	// NoInclude disables include resolution entirely.
	NoInclude bool
	// AllowExternalIncludes permits includes that resolve outside the config
	// directory tree. Off by default.
	AllowExternalIncludes bool
}

// Result is a loaded config tree plus any non-fatal loading notes.
type Result struct {
	// Path is the display path of the top config ("-" for stdin).
	Path string
	// Root is the synthetic top node; its children are the config's top-level
	// directives with includes expanded in place.
	Root *model.Node
	// Notes records include-resolution issues (skipped, unreadable, empty
	// globs, limits hit) that are surfaced to the user rather than hidden.
	Notes []string
}

type loader struct {
	opts      Options
	sandbox   string // absolute allowed root directory
	notes     []string
	fileCount int
	visiting  map[string]bool
}

// Load reads path (or stdin when path is "-") and returns the normalized tree.
func Load(path string, opts Options) (*Result, error) {
	l := &loader{opts: opts, visiting: map[string]bool{}}

	var (
		src      string
		baseDir  string
		dispPath string
		absSelf  string
	)

	if path == "-" {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, maxFileSize+1))
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		if len(b) > maxFileSize {
			return nil, fmt.Errorf("stdin config exceeds %d bytes", maxFileSize)
		}
		src = string(b)
		cwd, _ := os.Getwd()
		baseDir = cwd
		dispPath = "-"
	} else {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", path, err)
		}
		b, err := readCapped(abs)
		if err != nil {
			return nil, err
		}
		src = b
		baseDir = filepath.Dir(abs)
		dispPath = path
		absSelf = abs
	}

	l.sandbox = baseDir

	root := &model.Node{Name: "", File: dispPath}
	dirs, err := parseString(src)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", dispPath, err)
	}
	if absSelf != "" {
		l.visiting[absSelf] = true
	}
	root.Children = l.build(dirs, root, dispPath, baseDir, 0)

	sort.Strings(l.notes)
	return &Result{Path: dispPath, Root: root, Notes: dedup(l.notes)}, nil
}

func (l *loader) build(dirs []config.IDirective, parent *model.Node, curFile, curDir string, depth int) []*model.Node {
	var out []*model.Node
	for _, d := range dirs {
		if d.GetName() == "include" {
			out = append(out, l.expandInclude(d, parent, curFile, curDir, depth)...)
			continue
		}
		n := &model.Node{
			Name:   d.GetName(),
			Args:   paramsOf(d),
			File:   curFile,
			Line:   d.GetLine(),
			Parent: parent,
		}
		if b := d.GetBlock(); b != nil {
			n.Children = l.build(b.GetDirectives(), n, curFile, curDir, depth)
		}
		out = append(out, n)
	}
	return out
}

func (l *loader) expandInclude(d config.IDirective, parent *model.Node, curFile, curDir string, depth int) []*model.Node {
	target := includePath(d)
	if target == "" {
		l.note("include with no path at %s:%d skipped", curFile, d.GetLine())
		return nil
	}
	if l.opts.NoInclude {
		l.note("include %q at %s:%d skipped (--no-include)", model.Clean(target), curFile, d.GetLine())
		return nil
	}
	if depth >= maxIncludeDepth {
		l.note("include %q at %s:%d skipped: max include depth (%d) reached", model.Clean(target), curFile, d.GetLine(), maxIncludeDepth)
		return nil
	}

	pattern := target
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(curDir, pattern)
	}

	matches, err := filepath.Glob(pattern)
	if err != nil {
		l.note("include %q at %s:%d skipped: bad glob pattern", model.Clean(target), curFile, d.GetLine())
		return nil
	}
	if len(matches) == 0 {
		l.note("include %q at %s:%d matched no files", model.Clean(target), curFile, d.GetLine())
		return nil
	}
	sort.Strings(matches)

	var out []*model.Node
	for _, m := range matches {
		abs, err := filepath.Abs(filepath.Clean(m))
		if err != nil {
			l.note("include target %q skipped: %v", model.Clean(m), err)
			continue
		}
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() {
			continue
		}
		if !l.opts.AllowExternalIncludes && !withinSandbox(l.sandbox, abs) {
			l.note("include %q skipped: resolves outside config directory (use --allow-external-includes to permit)", model.Clean(m))
			continue
		}
		if l.visiting[abs] {
			l.note("include %q skipped: include cycle", model.Clean(m))
			continue
		}
		if l.fileCount >= maxTotalFiles {
			l.note("include processing stopped: max file count (%d) reached", maxTotalFiles)
			break
		}

		src, err := readCapped(abs)
		if err != nil {
			l.note("include %q skipped: %v", model.Clean(m), err)
			continue
		}
		l.fileCount++
		dirs, err := parseString(src)
		if err != nil {
			l.note("include %q skipped: parse error: %v", model.Clean(m), err)
			continue
		}

		disp := displayPath(abs)
		l.visiting[abs] = true
		out = append(out, l.build(dirs, parent, disp, filepath.Dir(abs), depth+1)...)
		delete(l.visiting, abs)
	}
	return out
}

func (l *loader) note(format string, a ...any) {
	l.notes = append(l.notes, fmt.Sprintf(format, a...))
}

func parseString(src string) ([]config.IDirective, error) {
	p := parser.NewStringParser(src,
		parser.WithSkipValidDirectivesErr(),
		parser.WithSkipComments(),
	)
	c, err := p.Parse()
	if err != nil {
		return nil, err
	}
	return c.GetDirectives(), nil
}

func paramsOf(d config.IDirective) []string {
	ps := d.GetParameters()
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Value)
	}
	return out
}

func includePath(d config.IDirective) string {
	if inc, ok := d.(*config.Include); ok && inc.IncludePath != "" {
		return inc.IncludePath
	}
	if ps := d.GetParameters(); len(ps) > 0 {
		return ps[0].Value
	}
	return ""
}

func readCapped(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxFileSize {
		return "", fmt.Errorf("file %s exceeds %d bytes", path, maxFileSize)
	}
	return string(b), nil
}

// withinSandbox reports whether abs is root itself or below it, after
// evaluating symlinks on root so a config placed behind a symlink still
// matches its own real tree.
func withinSandbox(root, abs string) bool {
	realRoot := root
	if r, err := filepath.EvalSymlinks(root); err == nil {
		realRoot = r
	}
	realAbs := abs
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		realAbs = r
	}
	rel, err := filepath.Rel(realRoot, realAbs)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func displayPath(abs string) string {
	if cwd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(cwd, abs); err == nil && !strings.HasPrefix(rel, "..") {
			return rel
		}
	}
	return abs
}

func dedup(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
