# ssrf-finder

A small Go tool for detecting potential server-side request forgery (SSRF) vulnerabilities. You feed it a list of URLs, each containing the placeholder `FUZZ` where a parameter value goes, and the tool replaces `FUZZ` with your callback domain and requests the resulting URL. If the target's response body contains that callback domain, the application is almost certainly fetching your URL — a potential SSRF.

Rewritten in 2026: modern Go, configurable callback/concurrency/timeouts, proxy support, graceful Ctrl+C handling and de-duplicated input. The original single-purpose behaviour is preserved — see [Changelog](#changelog).

## Features

- `FUZZ` placeholder substitution — one URL per line, first occurrence only
- Callback domain supplied by flag, no recompiling needed
- Configurable concurrency, timeout, user agent and output file
- HTTP/SOCKS proxy support (point it at Burp to watch every request)
- Redirects are not followed; response bodies capped at 1 MiB
- Duplicate input lines are de-duplicated; invalid lines are skipped with a warning
- Callback host is resolved once at startup so you fail fast on a typo
- Ctrl+C exits cleanly, keeping any results already written

## Requirements

- Go 1.24 or later to build:

  ```
  go build -o ssrf-finder .
  ```

- A callback host you control — a Burp Collaborator / OAST domain, an interaction server, or any HTTP listener you can see hits on.

## Usage

```
ssrf-finder -callback http://abc123.oastify.com [flags] [urls.txt]
```

URLs are read from the file given as the first argument, or from standard input.

| Flag | Default | Description |
|---|---|---|
| `-callback` | *(required)* | Callback host used to replace `FUZZ`, e.g. `http://abc123.oastify.com` |
| `-c` | `10` | Number of concurrent workers |
| `-timeout` | `5s` | Per-request timeout (Go duration, e.g. `10s`, `1m`) |
| `-insecure` | `true` | Skip TLS certificate verification |
| `-output` | `ssrf.log` | File vulnerable URLs are appended to |
| `-proxy` | *(none)* | HTTP(S) proxy, e.g. `http://127.0.0.1:8080` |
| `-v` | `false` | Verbose output for every request |
| `-ua` | recent Chrome | User-Agent header to send |

## Input format

One URL per line, each containing the literal string `FUZZ` where the callback domain should be substituted:

```
http://www.something.com/url?=FUZZ&somethingelse=whatever
```

`url.ParseRequestURI` validates each line, so malformed URLs are rejected with an `invalid url` message. Lines without `FUZZ` are skipped with a warning. You can generate candidate URLs yourself, for example from a parameter-mining tool:

```
cat urls.txt | ./ssrf-finder -callback http://abc123.oastify.com
echo 'https://www.something.com/?url=FUZZ&whatever=adsa&id=1' | ./ssrf-finder -callback http://abc123.oastify.com
./ssrf-finder -callback http://abc123.oastify.com urls.txt
```

Through Burp Suite, watching every request it makes:

```
./ssrf-finder -callback http://abc123.oastify.com -proxy http://127.0.0.1:8080 -c 5 urls.txt
```

## Worked example

Suppose you are testing `https://example.com/fetch?url=FUZZ` and you suspect the application requests the value of the `url` parameter.

1. Start a listener you control and note its hostname (for example `abc123.oastify.com` from Burp Collaborator).
2. Run the tool:

   ```
   echo 'https://example.com/fetch?url=FUZZ' | ./ssrf-finder -callback http://abc123.oastify.com
   ```

3. The tool rewrites the URL to `https://example.com/fetch?url=http://abc123.oastify.com` and issues a `GET` request with a Chrome user agent, ignoring TLS certificate errors, with a 5-second timeout at a concurrency of 10.
4. Watch your listener. If the target application fetches the URL, you will see an incoming HTTP request on your Collaborator or listener.
5. Independently of the listener, the tool also checks the target's HTTP response body: if it contains the callback hostname, the target is reflecting the fetched content and the URL is logged as vulnerable.

## How results are reported

- `[*] Vulnerable System Found! [*] <url>` — the response body contained the callback hostname; the original URL (with `FUZZ` still in place) is appended to `ssrf.log`.
- `[!] invalid url: <line>` — the line failed URL parsing.
- `[!] no FUZZ placeholder: <url>` — the line does not contain `FUZZ`.
- `[!] failed: <url> (<error>)` — the request failed (shown in verbose mode).
- `[*] <url> -> <status>` — request completed (shown in verbose mode).
- `[*] done: N tested, M vulnerable — results in ssrf.log` — end-of-run summary.

If `ssrf.log` exists when the run finishes, you have potential SSRF findings; if not, none were detected.

Non-200 responses are no longer printed for every URL — pass `-v` if you want to see every request and status.

## Changelog

- **2026 rewrite** — configurable `-callback` flag (previously a hardcoded Burp Collaborator domain compiled into the source), concurrency/timeout/proxy/user-agent flags, context-aware requests and cancellation, request de-duplication, 1 MiB response cap, startup DNS check of the callback host, non-200 noise suppressed (pass `-v`), end-of-run summary, unit tests and CI, updated to Go 1.24. Detection method is unchanged.
- **2019 original** — by @tomnomnom, adapted by @random-robbie.

## Disclaimer / Authorised use

This tool is for authorised security testing and responsible disclosure only. Do not use it against systems you do not have explicit permission to test.

## Credits

99% of this code is from @tomnomnom — the hero!

Raise issues if you have questions.

Use a VPS from DO

[![DigitalOcean Referral Badge](https://web-platforms.sfo2.cdn.digitaloceanspaces.com/WWW/Badge%201.svg)](https://www.digitalocean.com/?refcode=e22bbff5f6f1&utm_campaign=Referral_Invite&utm_medium=Referral_Program&utm_source=badge)

## Author

Robbie Wiggins — [What-Security](https://www.what-security.co.uk) · [GitHub](https://github.com/random-robbie)
