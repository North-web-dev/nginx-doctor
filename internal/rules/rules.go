// Package rules analyzes a normalized nginx config tree and reports graded
// findings. Every finding is derived only from directives actually present in
// the parsed tree; nothing is inferred beyond what the config states, and the
// few findings that depend on guessed runtime intent are marked advisory.
package rules

import (
	"fmt"
	"strings"

	"github.com/North-web-dev/nginx-doctor/internal/model"
)

// Options selects which categories to run.
type Options struct {
	Categories map[string]bool // nil or empty means all
}

func (o Options) on(cat string) bool {
	if len(o.Categories) == 0 {
		return true
	}
	return o.Categories[cat]
}

type analyzer struct {
	opts     Options
	findings []model.Finding
}

// Analyze runs every enabled check against the tree rooted at root.
func Analyze(root *model.Node, opts Options) []model.Finding {
	a := &analyzer{opts: opts}

	https := root.Dir("http")
	for _, h := range https {
		a.checkHTTP(h)
		for _, s := range h.Dir("server") {
			a.checkServer(s, h)
		}
		a.checkServerNameCollisions(h)
		a.checkUpstreams(h)
	}
	a.checkEvents(root)
	a.checkSSLProtocols(root)
	a.checkGlobalAutoindex(root)

	model.SortFindings(a.findings)
	return a.findings
}

func (a *analyzer) add(f model.Finding) {
	if !a.opts.on(f.Category) {
		return
	}
	a.findings = append(a.findings, f)
}

// ---- scope labelling ----

func serverLabel(s *model.Node) string {
	var names []string
	for _, sn := range s.Dir("server_name") {
		names = append(names, sn.Args...)
	}
	name := "_"
	if len(names) > 0 {
		name = strings.Join(names, ",")
	}
	ports := serverPorts(s)
	if len(ports) > 0 {
		return fmt.Sprintf("server %s:%s", name, strings.Join(ports, "/"))
	}
	return "server " + name
}

func (a *analyzer) scopeOf(n *model.Node) string {
	var loc *model.Node
	var srv *model.Node
	for p := n; p != nil; p = p.Parent {
		switch p.Name {
		case "location":
			if loc == nil {
				loc = p
			}
		case "server":
			srv = p
		}
	}
	switch {
	case srv != nil && loc != nil:
		return serverLabel(srv) + " > location " + loc.ArgStr()
	case srv != nil:
		return serverLabel(srv)
	case n.Name == "http" || hasAncestor(n, "http"):
		return "http"
	default:
		return "global"
	}
}

func hasAncestor(n *model.Node, name string) bool {
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Name == name {
			return true
		}
	}
	return false
}

// ---- listen / port helpers ----

func serverPorts(s *model.Node) []string {
	var ports []string
	seen := map[string]bool{}
	for _, l := range s.Dir("listen") {
		p := portOf(l.Args)
		if p != "" && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	return ports
}

func portOf(args []string) string {
	if len(args) == 0 {
		return ""
	}
	tok := args[0]
	if strings.HasPrefix(tok, "unix:") {
		return "unix"
	}
	// strip IPv6 brackets then take the piece after the last colon
	tok = strings.TrimPrefix(tok, "[")
	if i := strings.LastIndex(tok, ":"); i >= 0 {
		tok = tok[i+1:]
	}
	tok = strings.TrimSuffix(tok, "]")
	if tok == "" {
		return ""
	}
	for _, r := range tok {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return tok
}

func serverIsTLS(s *model.Node) bool {
	for _, l := range s.Dir("listen") {
		if l.HasArg("ssl") {
			return true
		}
	}
	if len(s.Dir("ssl_certificate")) > 0 || len(s.Dirs("ssl_protocols")) > 0 {
		return true
	}
	return false
}

func hasDefaultServer(s *model.Node) bool {
	for _, l := range s.Dir("listen") {
		if l.HasArg("default_server") {
			return true
		}
	}
	return false
}

// ---- http-level checks ----

func (a *analyzer) checkHTTP(h *model.Node) {
	// gzip
	gzipOn := false
	gzipPresent := false
	for _, g := range h.Dir("gzip") {
		gzipPresent = true
		if g.HasArg("on") {
			gzipOn = true
		}
	}
	switch {
	case gzipOn:
		a.add(model.Finding{Severity: model.Pass, Category: model.CatPerformance, Scope: "http",
			Title: "gzip compression enabled"})
	case gzipPresent:
		a.add(model.Finding{Severity: model.Warn, Category: model.CatPerformance, Scope: "http",
			Title: "gzip is turned off", Fix: "gzip on;", File: h.File, Line: h.DisplayLine()})
	default:
		a.add(model.Finding{Severity: model.Warn, Category: model.CatPerformance, Scope: "http",
			Title: "gzip not enabled (responses sent uncompressed)", Fix: "gzip on;", File: h.File, Line: h.DisplayLine()})
	}

	// server_tokens
	tokensSet := false
	for _, t := range h.Dirs("server_tokens") {
		tokensSet = true
		if t.HasArg("on") {
			a.add(model.Finding{Severity: model.Warn, Category: model.CatSecurity, Scope: a.scopeOf(t),
				Title: "server_tokens on leaks the nginx version in responses and errors",
				Fix:   "server_tokens off;", File: t.File, Line: t.Line})
		} else if t.HasArg("off") {
			a.add(model.Finding{Severity: model.Pass, Category: model.CatSecurity, Scope: a.scopeOf(t),
				Title: "server_tokens off (version hidden)"})
		}
	}
	if !tokensSet {
		a.add(model.Finding{Severity: model.Warn, Category: model.CatSecurity, Scope: "http",
			Title: "server_tokens not set; defaults to on and leaks the nginx version",
			Fix:   "server_tokens off;", File: h.File, Line: h.DisplayLine()})
	}

	// client_max_body_size
	if len(h.Dirs("client_max_body_size")) == 0 {
		a.add(model.Finding{Severity: model.Warn, Category: model.CatSecurity, Scope: "http",
			Title: "client_max_body_size not set (defaults to 1m); set it explicitly to bound request bodies",
			Fix:   "client_max_body_size 10m;", File: h.File, Line: h.DisplayLine()})
	}

	// proxy_buffering off
	for _, pb := range h.Dirs("proxy_buffering") {
		if pb.HasArg("off") {
			a.add(model.Finding{Severity: model.Warn, Category: model.CatPerformance, Scope: a.scopeOf(pb), Advisory: true,
				Title: "proxy_buffering off streams every response unbuffered; keep it on unless you specifically need streaming",
				Fix:   "proxy_buffering on;", File: pb.File, Line: pb.Line})
		}
	}
}

func (a *analyzer) checkEvents(root *model.Node) {
	events := root.Dir("events")
	if len(events) == 0 {
		return
	}
	for _, e := range events {
		wc := e.Dir("worker_connections")
		if len(wc) == 0 {
			a.add(model.Finding{Severity: model.Warn, Category: model.CatPerformance, Scope: "events",
				Title: "worker_connections not set (defaults to 512); raise it for busy servers",
				Fix:   "worker_connections 1024;", File: e.File, Line: e.DisplayLine()})
			continue
		}
		for _, w := range wc {
			if len(w.Args) == 1 && isSmallInt(w.Args[0], 1024) {
				a.add(model.Finding{Severity: model.Warn, Category: model.CatPerformance, Scope: "events",
					Title: fmt.Sprintf("worker_connections %s is low", model.Clean(w.Args[0])),
					Fix:   "worker_connections 1024;", File: w.File, Line: w.Line})
			}
		}
	}
}

// ---- server-level checks ----

func (a *analyzer) checkServer(s, h *model.Node) {
	scope := serverLabel(s)
	tls := serverIsTLS(s)

	a.checkSecurityHeaders(s, h, scope, tls)
	a.checkDotfiles(s, scope)
	a.checkHTTP2(s, h, scope, tls)
	a.checkCiphers(s, scope, tls)
	a.checkHeaderInheritance(s, h)
	a.checkIfMisuse(s)
	a.checkRootPitfalls(s)
	a.checkProxyPass(s)
	a.checkTLSPassthrough(s, scope, tls)
	a.checkAutoindex(s)
}

var securityHeaders = []struct{ canonical, key string }{
	{"X-Content-Type-Options", "x-content-type-options"},
	{"X-Frame-Options", "x-frame-options"},
	{"Referrer-Policy", "referrer-policy"},
	{"Content-Security-Policy", "content-security-policy"},
}

func headerSet(nodes []*model.Node, key string) bool {
	for _, n := range nodes {
		if len(n.Args) > 0 && strings.EqualFold(n.Args[0], key) {
			return true
		}
	}
	return false
}

func (a *analyzer) checkSecurityHeaders(s, h *model.Node, scope string, tls bool) {
	if !servesContent(s) || redirectOnly(s) {
		return
	}
	// Collect add_header directives visible to this server: http-level,
	// server-level, and location-level.
	nodes := append([]*model.Node{}, h.Dir("add_header")...)
	nodes = append(nodes, s.Dirs("add_header")...)

	var missing []string
	fixes := []string{}
	if tls && !headerSet(nodes, "Strict-Transport-Security") {
		missing = append(missing, "Strict-Transport-Security")
		fixes = append(fixes, `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;`)
	}
	for _, hdr := range securityHeaders {
		if !headerSet(nodes, hdr.canonical) {
			missing = append(missing, hdr.canonical)
			switch hdr.canonical {
			case "X-Content-Type-Options":
				fixes = append(fixes, `add_header X-Content-Type-Options "nosniff" always;`)
			case "X-Frame-Options":
				fixes = append(fixes, `add_header X-Frame-Options "SAMEORIGIN" always;`)
			case "Referrer-Policy":
				fixes = append(fixes, `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`)
			case "Content-Security-Policy":
				fixes = append(fixes, `add_header Content-Security-Policy "default-src 'self'" always;`)
			}
		}
	}
	if len(missing) == 0 {
		a.add(model.Finding{Severity: model.Pass, Category: model.CatSecurity, Scope: scope,
			Title: "security response headers present"})
		return
	}
	a.add(model.Finding{Severity: model.Warn, Category: model.CatSecurity, Scope: scope,
		Title: "missing security headers: " + strings.Join(missing, ", "),
		Fix:   strings.Join(fixes, " "), File: s.File, Line: s.DisplayLine()})
}

func (a *analyzer) checkDotfiles(s *model.Node, scope string) {
	if !servesFiles(s) {
		return
	}
	for _, loc := range s.Dirs("location") {
		if locationMatchesDotfiles(loc) && locationDenies(loc) {
			a.add(model.Finding{Severity: model.Pass, Category: model.CatSecurity, Scope: scope,
				Title: "dotfiles (.git/.env …) denied"})
			return
		}
	}
	a.add(model.Finding{Severity: model.Warn, Category: model.CatSecurity, Scope: scope,
		Title: "serves files from disk with no dotfile deny rule; .git, .env and .htpasswd may be downloadable",
		Fix:   `location ~ /\. { deny all; return 404; }`, File: s.File, Line: s.DisplayLine()})
}

func (a *analyzer) checkHTTP2(s, h *model.Node, scope string, tls bool) {
	if !tls {
		return
	}
	http2On := false
	for _, l := range s.Dir("listen") {
		if l.HasArg("http2") {
			http2On = true
		}
	}
	for _, d := range append(s.Dirs("http2"), h.Dir("http2")...) {
		if d.HasArg("on") {
			http2On = true
		}
	}
	if http2On {
		a.add(model.Finding{Severity: model.Pass, Category: model.CatPerformance, Scope: scope,
			Title: "HTTP/2 enabled on TLS listener"})
		return
	}
	a.add(model.Finding{Severity: model.Warn, Category: model.CatPerformance, Scope: scope,
		Title: "TLS listener without HTTP/2",
		Fix:   "http2 on;  # nginx >= 1.25.1, or add 'http2' to the listen directive", File: s.File, Line: s.DisplayLine()})
}

var weakCipherTokens = []string{"RC4", "NULL", "EXPORT", "MD5", "ANULL", "ENULL", "LOW", "DES-"}

func (a *analyzer) checkCiphers(s *model.Node, scope string, tls bool) {
	if !tls {
		return
	}
	ciphers := s.Dirs("ssl_ciphers")
	if len(ciphers) == 0 {
		a.add(model.Finding{Severity: model.Warn, Category: model.CatSecurity, Scope: scope, Advisory: true,
			Title: "TLS enabled without an explicit ssl_ciphers list (relies on build defaults)",
			Fix:   "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'; ssl_prefer_server_ciphers off;",
			File:  s.File, Line: s.DisplayLine()})
		return
	}
	for _, c := range ciphers {
		up := strings.ToUpper(c.ArgStr())
		var bad []string
		for _, w := range weakCipherTokens {
			if strings.Contains(up, w) {
				bad = append(bad, strings.TrimSuffix(w, "-"))
			}
		}
		if len(bad) > 0 {
			a.add(model.Finding{Severity: model.Fail, Category: model.CatSecurity, Scope: scope,
				Title: "ssl_ciphers includes weak/broken ciphers: " + strings.Join(bad, ", "),
				Fix:   "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';",
				File:  c.File, Line: c.Line})
		}
	}
}

// checkHeaderInheritance flags the classic add_header-does-not-inherit trap:
// a block with its own add_header silently drops every add_header set by an
// ancestor block.
func (a *analyzer) checkHeaderInheritance(s, h *model.Node) {
	outer := map[string]bool{}
	for _, ah := range h.Dir("add_header") {
		if len(ah.Args) > 0 {
			outer[strings.ToLower(ah.Args[0])] = true
		}
	}
	// server inherits from http; a server with its own add_header drops http's.
	srvHeaders := s.Dir("add_header")
	if len(srvHeaders) > 0 && len(outer) > 0 {
		dropped := droppedHeaders(outer, srvHeaders)
		if len(dropped) > 0 {
			a.add(model.Finding{Severity: model.Warn, Category: model.CatSecurity, Scope: serverLabel(s),
				Title: "add_header here resets inherited headers; these from the http block no longer apply: " + strings.Join(dropped, ", "),
				Fix:   "re-declare the dropped add_header lines in this block, or keep all add_header at one level",
				File:  srvHeaders[0].File, Line: srvHeaders[0].Line})
		}
	}
	// locations inherit from server (or http if server has none).
	serverLevel := map[string]bool{}
	src := srvHeaders
	if len(src) == 0 {
		serverLevel = outer
	} else {
		for _, ah := range src {
			if len(ah.Args) > 0 {
				serverLevel[strings.ToLower(ah.Args[0])] = true
			}
		}
	}
	for _, loc := range s.Dir("location") {
		locHeaders := loc.Dir("add_header")
		if len(locHeaders) == 0 || len(serverLevel) == 0 {
			continue
		}
		dropped := droppedHeaders(serverLevel, locHeaders)
		if len(dropped) > 0 {
			a.add(model.Finding{Severity: model.Warn, Category: model.CatSecurity, Scope: a.scopeOf(loc),
				Title: "add_header here resets inherited headers; these from the enclosing block no longer apply: " + strings.Join(dropped, ", "),
				Fix:   "re-declare the dropped add_header lines in this location, or keep all add_header at one level",
				File:  locHeaders[0].File, Line: locHeaders[0].Line})
		}
	}
}

func droppedHeaders(outer map[string]bool, inner []*model.Node) []string {
	innerSet := map[string]bool{}
	for _, n := range inner {
		if len(n.Args) > 0 {
			innerSet[strings.ToLower(n.Args[0])] = true
		}
	}
	var dropped []string
	for k := range outer {
		if !innerSet[k] {
			dropped = append(dropped, k)
		}
	}
	return dropped
}

func (a *analyzer) checkIfMisuse(s *model.Node) {
	for _, ifn := range s.Dirs("if") {
		cond := ifn.ArgStr()
		reason := ""
		if condTestsFile(cond) {
			reason = "tests file existence with if; use try_files"
		} else {
			for _, inner := range []string{"rewrite", "set", "proxy_pass", "fastcgi_pass", "root", "try_files"} {
				if len(ifn.Dir(inner)) > 0 {
					reason = fmt.Sprintf("contains %s inside if, which runs per request and breaks subtly; use try_files or map", inner)
					break
				}
			}
		}
		if reason != "" {
			a.add(model.Finding{Severity: model.Warn, Category: model.CatCorrectness, Scope: a.scopeOf(ifn),
				Title: "\"if is evil\" here: " + reason,
				Fix:   "move the logic to try_files, a map block, or a separate server/location", File: ifn.File, Line: ifn.Line})
		}
	}
}

func (a *analyzer) checkRootPitfalls(s *model.Node) {
	locs := s.Dir("location")
	rootCount := 0
	for _, loc := range locs {
		if len(loc.Dir("root")) > 0 {
			rootCount++
		}
		// alias trailing-slash mismatch (prefix locations only)
		if len(loc.Args) >= 1 && !isRegexLocation(loc) {
			match := loc.Args[len(loc.Args)-1]
			for _, al := range loc.Dir("alias") {
				if len(al.Args) == 1 {
					alias := al.Args[0]
					if strings.HasSuffix(match, "/") != strings.HasSuffix(alias, "/") {
						a.add(model.Finding{Severity: model.Warn, Category: model.CatCorrectness, Scope: a.scopeOf(loc),
							Title: "alias trailing slash does not match the location prefix (a common path-traversal / 404 trap)",
							Fix:   "make the location and alias agree on the trailing slash", File: al.File, Line: al.Line})
					}
				}
			}
		}
	}
	if rootCount >= 2 {
		a.add(model.Finding{Severity: model.Warn, Category: model.CatCorrectness, Scope: serverLabel(s), Advisory: true,
			Title: fmt.Sprintf("root repeated in %d locations; a per-location root is error-prone", rootCount),
			Fix:   "declare root once in the server block and let locations inherit it", File: s.File, Line: s.DisplayLine()})
	}
}

func (a *analyzer) checkProxyPass(s *model.Node) {
	for _, pp := range s.Dirs("proxy_pass") {
		url := pp.ArgStr()
		if strings.Contains(url, "$") {
			a.add(model.Finding{Severity: model.Warn, Category: model.CatSecurity, Scope: a.scopeOf(pp), Advisory: true,
				Title: "proxy_pass target contains a variable (" + model.Clean(firstVar(url)) + "); if any part derives from client input this is an SSRF / open-proxy risk",
				Fix:   "proxy to a fixed upstream, or validate and whitelist the dynamic value before using it", File: pp.File, Line: pp.Line})
		}
	}
}

func (a *analyzer) checkTLSPassthrough(s *model.Node, scope string, tls bool) {
	if !tls || len(s.Dir("ssl_certificate")) == 0 {
		return
	}
	for _, pp := range s.Dirs("proxy_pass") {
		if strings.HasPrefix(strings.ToLower(pp.ArgStr()), "https://") {
			a.add(model.Finding{Severity: model.Warn, Category: model.CatCorrectness, Scope: scope, Advisory: true,
				Title: "this server terminates TLS and re-encrypts to an https upstream; if you intended SNI/TLS passthrough, terminate in a stream{} block with ssl_preread instead",
				Fix:   "for passthrough: stream { server { listen 443; ssl_preread on; proxy_pass $upstream; } } — no ssl_certificate at this layer", File: pp.File, Line: pp.Line})
			return
		}
	}
}

func (a *analyzer) checkAutoindex(s *model.Node) {
	for _, ai := range s.Dirs("autoindex") {
		if ai.HasArg("on") {
			a.add(model.Finding{Severity: model.Warn, Category: model.CatSecurity, Scope: a.scopeOf(ai),
				Title: "autoindex on exposes a browsable directory listing",
				Fix:   "autoindex off;", File: ai.File, Line: ai.Line})
		}
	}
}

func (a *analyzer) checkGlobalAutoindex(root *model.Node) {
	// autoindex can also sit at http level directly (outside a server).
	for _, h := range root.Dir("http") {
		for _, ai := range h.Dir("autoindex") {
			if ai.HasArg("on") {
				a.add(model.Finding{Severity: model.Warn, Category: model.CatSecurity, Scope: "http",
					Title: "autoindex on at http level exposes browsable directory listings",
					Fix:   "autoindex off;", File: ai.File, Line: ai.Line})
			}
		}
	}
}

func (a *analyzer) checkServerNameCollisions(h *model.Node) {
	type key struct{ port, name string }
	count := map[key][]*model.Node{}
	servers := h.Dir("server")
	for _, s := range servers {
		ports := serverPorts(s)
		if len(ports) == 0 {
			ports = []string{""}
		}
		for _, sn := range s.Dir("server_name") {
			for _, name := range sn.Args {
				if name == "" {
					continue
				}
				for _, p := range ports {
					count[key{p, name}] = append(count[key{p, name}], s)
				}
			}
		}
	}
	for k, sv := range count {
		if len(sv) >= 2 {
			a.add(model.Finding{Severity: model.Warn, Category: model.CatCorrectness, Scope: "http",
				Title: fmt.Sprintf("server_name %q is defined on %d servers for port %s; nginx uses the first and ignores the rest", model.Clean(k.name), len(sv), portLabel(k.port)),
				Fix:   "remove the duplicate server_name or merge the server blocks", File: sv[0].File, Line: sv[0].DisplayLine()})
		}
	}

	// ambiguous default server per port
	portServers := map[string][]*model.Node{}
	for _, s := range servers {
		for _, p := range serverPorts(s) {
			portServers[p] = append(portServers[p], s)
		}
	}
	for p, sv := range portServers {
		if len(sv) < 2 {
			continue
		}
		hasDefault := false
		for _, s := range sv {
			if hasDefaultServer(s) {
				hasDefault = true
			}
		}
		if !hasDefault {
			a.add(model.Finding{Severity: model.Warn, Category: model.CatCorrectness, Scope: "http", Advisory: true,
				Title: fmt.Sprintf("%d servers listen on port %s with no default_server; the first one silently becomes the default", len(sv), p),
				Fix:   "mark the intended default with: listen " + p + " default_server;", File: sv[0].File, Line: sv[0].DisplayLine()})
		}
	}
}

func (a *analyzer) checkUpstreams(h *model.Node) {
	for _, up := range h.Dir("upstream") {
		name := up.ArgStr()
		if len(up.Dir("keepalive")) == 0 {
			a.add(model.Finding{Severity: model.Warn, Category: model.CatPerformance, Scope: "upstream " + name,
				Title: "upstream has no keepalive; every proxied request opens a new upstream connection",
				Fix:   "add 'keepalive 32;' to the upstream block (and set proxy_http_version 1.1; proxy_set_header Connection \"\";)", File: up.File, Line: up.DisplayLine()})
		}
	}
}

// checkSSLProtocols flags every ssl_protocols directive (root.Dirs descends
// into http and server blocks) that enables an obsolete protocol.
func (a *analyzer) checkSSLProtocols(root *model.Node) {
	for _, p := range root.Dirs("ssl_protocols") {
		legacy := legacyProtocols(p)
		if len(legacy) > 0 {
			a.add(model.Finding{Severity: model.Fail, Category: model.CatSecurity, Scope: a.scopeOf(p),
				Title: "ssl_protocols enables obsolete protocols: " + strings.Join(legacy, ", "),
				Fix:   "ssl_protocols TLSv1.2 TLSv1.3;", File: p.File, Line: p.Line})
		} else if len(p.Args) > 0 {
			a.add(model.Finding{Severity: model.Pass, Category: model.CatSecurity, Scope: a.scopeOf(p),
				Title: "ssl_protocols restricted to modern TLS"})
		}
	}
}

// ---- small predicates ----

func legacyProtocols(p *model.Node) []string {
	var out []string
	for _, a := range p.Args {
		switch strings.ToUpper(a) {
		case "SSLV2", "SSLV3", "TLSV1", "TLSV1.1":
			out = append(out, a)
		}
	}
	return out
}

func servesContent(s *model.Node) bool {
	for _, d := range []string{"root", "index", "try_files", "alias", "proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass"} {
		if len(s.Dirs(d)) > 0 {
			return true
		}
	}
	return false
}

func servesFiles(s *model.Node) bool {
	return len(s.Dirs("root")) > 0 || len(s.Dirs("alias")) > 0
}

func redirectOnly(s *model.Node) bool {
	if servesFiles(s) {
		return false
	}
	for _, d := range []string{"proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass"} {
		if len(s.Dirs(d)) > 0 {
			return false
		}
	}
	for _, r := range s.Dirs("return") {
		if len(r.Args) > 0 && strings.HasPrefix(r.Args[0], "30") {
			return true
		}
	}
	return false
}

func locationMatchesDotfiles(loc *model.Node) bool {
	for _, a := range loc.Args {
		if strings.Contains(a, `\.`) {
			return true
		}
	}
	return false
}

func locationDenies(loc *model.Node) bool {
	for _, d := range loc.Dir("deny") {
		if d.HasArg("all") {
			return true
		}
	}
	for _, r := range loc.Dir("return") {
		if len(r.Args) > 0 && (r.Args[0] == "403" || r.Args[0] == "404" || r.Args[0] == "444") {
			return true
		}
	}
	return false
}

func isRegexLocation(loc *model.Node) bool {
	return len(loc.Args) >= 2 && (loc.Args[0] == "~" || loc.Args[0] == "~*")
}

func condTestsFile(cond string) bool {
	for _, t := range []string{"-f", "-e", "-d", "-x"} {
		if strings.Contains(cond, t) {
			return true
		}
	}
	return false
}

func firstVar(url string) string {
	i := strings.Index(url, "$")
	if i < 0 {
		return url
	}
	end := i + 1
	for end < len(url) && (isIdent(url[end])) {
		end++
	}
	return url[i:end]
}

func isIdent(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func isSmallInt(s string, threshold int) bool {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
		n = n*10 + int(r-'0')
		if n >= threshold {
			return false
		}
	}
	return s != ""
}

func portLabel(p string) string {
	if p == "" {
		return "(unspecified)"
	}
	return p
}
