# ssrf-finder

A small Go tool for detecting potential server-side request forgery (SSRF) vulnerabilities. You feed it a list of URLs, each containing the placeholder `FUZZ` where a parameter value goes, and the tool replaces `FUZZ` with a unique callback domain and requests the resulting URL. If the target's response body contains that callback domain, the application is almost certainly fetching your URL — a potential SSRF.

## Requirements

- Go (to build from source):

  ```
  go build -o ssrf-finder ssrf-finder.go
  ```

- A callback/collaborator domain. The replacement domain is compiled in as a Burp Collaborator subdomain (`*.burpcollaborator.net`), so it only works as-is if you control that particular Collaborator server. Fork the code and change the `strings.Replace` domain in `fetchURL` to your own Collaborator or listener hostname before using it.
- URLs must resolve to an IP address (the tool performs a DNS lookup first and skips hosts that do not resolve).

## Input format

The tool reads one URL per line from standard input, or from a file given as the first argument. Each URL must be a fully qualified URL containing the literal string `FUZZ`, which marks where the callback domain will be substituted:

```
http://www.something.com/url?=FUZZ&somethingelse=whatever
```

`url.ParseRequestURI` validates each line, so malformed URLs are rejected with an `invalid url` message.

Only the first occurrence of `FUZZ` in a URL is replaced. You can generate candidate URLs yourself, for example from a parameter-mining tool, using a pipeline like:

```
cat urls.txt | ./ssrf-finder
```

or a single test URL:

```
echo https://www.something.com/?url=FUZZ&whatever=adsa&id=1 | ./ssrf-finder
```

or from a file:

```
./ssrf-finder urls.txt
```

## Worked example

Suppose you are testing `https://example.com/fetch?url=FUZZ` and you suspect the application requests the value of the `url` parameter.

1. Point `fetchURL` at your own Collaborator domain (or a listener you control, such as an HTTP server on your VPS).
2. Run the tool:

   ```
   echo 'https://example.com/fetch?url=FUZZ' | ./ssrf-finder
   ```

3. The tool rewrites the URL to `https://example.com/fetch?url=http://omeg0ivn7k95wloyezah7zcqghm7aw.burpcollaborator.net` and issues a `GET` request with a Chrome user agent, ignoring TLS certificate errors, with a 5-second timeout, at a concurrency of 12.
4. Watch your listener. If the target application fetches the URL, you will see an incoming HTTP request on your Collaborator or listener.
5. Independently of the listener, the tool also checks the target's HTTP response body: if it contains the callback domain, the target is reflecting the fetched content and the URL is logged as vulnerable.

## How results are reported

Progress messages go to standard output as the tool runs:

- `invalid url: <line>` — the line failed URL parsing.
- `does not resolve: <url>` — the hostname has no DNS record.
- `failed to fetch: <url> (<error>)` — the request failed.
- `non-200 response code: <url> (<status>)` — the server replied with a non-200 status.
- `200 response code: <url> (<status>)` — the server replied with 200.

When the response body contains the callback domain, the tool prints:

```
[*] Vulnerable System Found! [*]
```

and appends the URL to `ssrf.log` in the current directory. If `ssrf.log` exists when the run finishes, you have potential SSRF findings; if not, none were detected.

## Disclaimer / Authorised use

This tool is for authorised security testing and responsible disclosure only. Do not use it against systems you do not have explicit permission to test.

## Credits

99% of this code is from @tomnomnom — the hero!

Raise issues if you have questions.

Use a VPS from DO

[![DigitalOcean Referral Badge](https://web-platforms.sfo2.cdn.digitaloceanspaces.com/WWW/Badge%201.svg)](https://www.digitalocean.com/?refcode=e22bbff5f6f1&utm_campaign=Referral_Invite&utm_medium=Referral_Program&utm_source=badge)

## Author

Robbie Wiggins — [What-Security](https://www.what-security.co.uk) · [GitHub](https://github.com/random-robbie)
