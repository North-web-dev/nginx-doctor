# nginx-doctor

[![Release](https://img.shields.io/github/v/release/North-web-dev/nginx-doctor?sort=semver)](https://github.com/North-web-dev/nginx-doctor/releases) [![Go Reference](https://pkg.go.dev/badge/github.com/North-web-dev/nginx-doctor.svg)](https://pkg.go.dev/github.com/North-web-dev/nginx-doctor) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) ![Go](https://img.shields.io/github/go-mod/go-version/North-web-dev/nginx-doctor)

Lint your nginx config for security, performance, and correctness mistakes — and get the exact fix for each.

`nginx-doctor` is a zero-config Go binary. Point it at an `nginx.conf` (or pipe one in) and it parses the config — resolving `include` directives — and prints graded `PASS` / `WARN` / `FAIL` findings grouped by server and location, each with a one-line fix and a final summary grade.

It is **read-only**. It never edits, reloads, or talks to a running nginx. It only reads the config files you point it at.

## The problem

nginx configs accumulate the same silent mistakes, and most of them never throw an error — they just quietly weaken the server:

- Legacy TLS (`TLSv1` / `TLSv1.1`) left enabled years after it should have been removed.
- Missing security headers (HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, CSP).
- `server_tokens on`, leaking the exact nginx version in every response and error page.
- Dotfiles served straight off disk — `.git/`, `.env`, `.htpasswd` downloadable by anyone.
- The classic **`add_header` doesn't inherit** trap: one `add_header` in an inner block silently drops every header set by the parent, so your HSTS header vanishes exactly where you added a cache header.
- `if` used where `try_files` or `map` belongs ("if is evil").
- Duplicate `server_name` and ambiguous `default_server`.
- gzip and HTTP/2 left off.
- Terminating TLS at the HTTP layer when the intent was SNI/TLS passthrough (which needs a `stream { ssl_preread }` block, not an HTTP TLS-terminating proxy).

People eyeball the config, or they learn the hard way in production. `nginx-doctor` sweeps the whole config in one pass and reports every one of these it can actually see.

## Install

With Go 1.25 or newer:

```
go install github.com/North-web-dev/nginx-doctor/cmd/nginx-doctor@latest
```

Or download a prebuilt binary for Linux, macOS, or Windows (amd64 + arm64) from the [releases page](https://github.com/North-web-dev/nginx-doctor/releases), verify it against `checksums.txt`, and drop it on your `PATH`.

Docker — build the distroless, static, non-root image from source and lint your config read-only:

```
docker build -t nginx-doctor .
docker run --rm -v /etc/nginx:/etc/nginx:ro nginx-doctor /etc/nginx/nginx.conf
```

## Usage

```
nginx-doctor [flags] [path]
```

- `path` — the config to lint. With no path, `nginx-doctor` auto-discovers `/etc/nginx/nginx.conf` (and a couple of other common locations). Use `-` to read from stdin.

Flags:

| Flag | Effect |
|---|---|
| `--json` | emit findings as JSON |
| `--severity warn\|fail` | only show findings at or above this severity |
| `--only a,b,c` | limit to categories: `security`, `perf`, `correctness` |
| `--no-include` | do not resolve `include` directives |
| `--allow-external-includes` | allow includes that resolve outside the config directory |
| `--fix-preview` | after the report, print a copy-pasteable list of suggested directives |
| `--no-color` | disable ANSI colour |
| `--version` | print version |
| `-h`, `--help` | print help |

Exit codes:

- `0` — no `FAIL` findings
- `1` — at least one `FAIL` finding
- `2` — parse or usage error

The exit code makes `nginx-doctor` drop straight into CI or a pre-deploy gate.

## Example

Run against a deliberately flawed config:

```
$ nginx-doctor --no-color testdata/bad/nginx.conf
nginx-doctor — testdata/bad/nginx.conf

http
  WARN  [perf] gzip is turned off  [testdata/bad/nginx.conf:9]
        fix: gzip on;
  WARN  [security] server_tokens on leaks the nginx version in responses and errors  [testdata/bad/nginx.conf:10]
        fix: server_tokens off;

server example.com:80/443
  FAIL  [security] ssl_ciphers includes weak/broken ciphers: RC4, NULL, ANULL, DES  [testdata/bad/nginx.conf:25]
        fix: ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
  FAIL  [security] ssl_protocols enables obsolete protocols: TLSv1, TLSv1.1  [testdata/bad/nginx.conf:24]
        fix: ssl_protocols TLSv1.2 TLSv1.3;
  WARN  [security] add_header here resets inherited headers; these from the http block no longer apply: x-frame-options  [testdata/bad/nginx.conf:31]
        fix: re-declare the dropped add_header lines in this block, or keep all add_header at one level
  WARN  [security] serves files from disk with no dotfile deny rule; .git, .env and .htpasswd may be downloadable  [testdata/bad/nginx.conf:18]
        fix: location ~ /\. { deny all; return 404; }
  WARN  [security] autoindex on exposes a browsable directory listing  [testdata/bad/nginx.conf:29]
        fix: autoindex off;

server example.com:80/443 > location /legacy
  WARN  [correctness] "if is evil" here: tests file existence with if; use try_files  [testdata/bad/nginx.conf:40]
        fix: move the logic to try_files, a map block, or a separate server/location

summary: 2 FAIL, 19 WARN, 0 PASS  —  score 0/100, grade F
```

(Trimmed for the README; the real run prints every finding.) A clean config reports only `PASS` lines and grades `A` with exit code `0`.

## What it checks

Every finding comes from a directive actually present in the parsed config. `nginx-doctor` never invents a problem, and the handful of checks that depend on guessed runtime intent are explicitly marked `(advisory)`.

### Security

- `ssl_protocols` enabling `TLSv1`, `TLSv1.1`, `SSLv2`, or `SSLv3` — **FAIL**.
- `ssl_ciphers` containing broken ciphers (`RC4`, `NULL`, `aNULL`, `eNULL`, `EXPORT`, `MD5`, `LOW`, `DES`) — **FAIL**; TLS enabled with no explicit cipher list — **WARN** (advisory).
- `server_tokens on`, or unset (defaults to on) — **WARN**.
- Missing security headers (HSTS on TLS servers, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, CSP) on content-serving servers — **WARN**.
- Serving files from disk with no `location ~ /\.` deny rule for dotfiles — **WARN**.
- `autoindex on` — **WARN**.
- `client_max_body_size` unset — **WARN**.
- The `add_header`-doesn't-inherit trap: an inner block whose own `add_header` silently drops headers set by its parent — **WARN**, naming the dropped headers.
- `proxy_pass` to a target built from a variable (`$host` and friends) — **WARN** (advisory, SSRF/open-proxy risk).

### Performance

- gzip off or unset — **WARN**.
- A TLS listener with no HTTP/2 — **WARN**.
- Low `worker_connections` — **WARN**.
- An `upstream` block with no `keepalive` — **WARN**.
- `proxy_buffering off` — **WARN** (advisory).

### Correctness

- Duplicate / overlapping `server_name` on the same port — **WARN**.
- Several servers on one port with no `default_server` — **WARN** (advisory).
- `if` used for file tests or wrapping `rewrite`/`set`/`proxy_pass` ("if is evil") — **WARN**.
- `alias` whose trailing slash disagrees with the location prefix; `root` repeated across many locations — **WARN**.
- A server that terminates TLS and re-encrypts to an `https://` upstream, where the intent may be SNI/TLS passthrough (which belongs in `stream { ssl_preread }`) — **WARN** (advisory).

## Include resolution and the sandbox

`nginx-doctor` resolves `include` directives relative to the directory of the config being linted, the same way nginx does, so a config that splits servers across `conf.d/*.conf` and `sites-enabled/*` is analyzed as a whole.

For safety, include resolution is **sandboxed to the config directory tree by default**. A config that includes `/etc/shadow`, or escapes its own directory with `../`, has that include skipped and a note printed rather than silently reading the file. Pass `--allow-external-includes` to lift the sandbox when you genuinely include files from elsewhere. Resolution is also bounded in per-file size, include depth, and total file count, and cyclic includes are detected and broken — a hostile or broken config cannot make the linter read arbitrary files or loop forever.

When an include glob matches nothing, or a matched file can't be read or parsed, `nginx-doctor` says so in a `config loading` section instead of pretending the directives were there.

## Honest limits

- This is **static analysis**. It reports what the config says, not what nginx does at runtime. It cannot know which servers actually serve HTML, whether a backend is trusted, or whether a TLS-terminating proxy was meant to be a passthrough. Findings that depend on that kind of inferred intent are marked `(advisory)`.
- Includes that resolve outside the config directory tree are skipped by default (see above). If your layout genuinely spans directories, use `--allow-external-includes`.
- `nginx-doctor` does not evaluate `map` tables, Lua, or `perl` blocks, and it does not model directive inheritance beyond the `add_header` reset rule it checks for explicitly.
- It is read-only by design. `--fix-preview` prints suggested directive snippets but never writes a file or touches nginx.

## Security notes

- File access is read-only; the tool never writes to or reloads nginx.
- Include resolution is sandboxed, size-capped, depth-capped, and cycle-safe (see above), so a config from an untrusted multi-tenant panel can't turn the linter into a file-read primitive.
- Every string taken from the config — server names, paths, directive arguments — is stripped of control characters and terminal escape sequences before it is printed, in both the text and JSON output. A config that embeds ANSI escapes in a `server_name` cannot inject them into your terminal.

## Building from source

```
git clone https://github.com/North-web-dev/nginx-doctor
cd nginx-doctor
go build ./cmd/nginx-doctor
go test ./... -race
```

## Support

If `nginx-doctor` saved you a bad night, a ⭐ on the repo genuinely helps — and tips are appreciated:

| Coin | Address |
|---|---|
| **BTC** | `bc1q0sfghv7yfl594gjurhyhlhdgm0dtwh4dkjha36` |
| **ETH / USDT-ERC20 / BNB-BEP20** | `0xB827b5a8B6c5111946c5D872933b2C23484E87dE` |
| **SOL** | `3ch5aHrPp3CierhiNXmqmtFH2dMHh6Gfv7a97KtLMMCh` |
| **USDT-TRC20 / TRX** | `TUAyz7TjgJdFVD2oFHWUUTNrzzAnBRgySG` |
| **TON** | `UQAJmYVuR3hh02etjaPKJF-h6jcpdSnq9ZIFvI64NEskS6tx` |

## License

MIT — see [LICENSE](LICENSE).
