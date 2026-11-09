package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatih/color"
)

const (
	defaultTimeout = 5 * time.Second
	defaultConcurr = 10
	defaultOutput  = "ssrf.log"

	// defaultUserAgent: current stable Chrome on Windows. Chrome reports
	// Windows NT 10.0 even on Windows 11; the minor version is frozen.
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
)

// rotatedUserAgents are used when -rotate-ua is set. Kept to a handful of
// common, current desktop browsers so requests blend into normal traffic.
var rotatedUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0",
}

// uaPicker returns the User-Agent for a request: a fixed one by default, or
// round-robin over rotatedUserAgents when rotation is enabled.
type uaPicker struct {
	rotate bool
	n      atomic.Uint64
}

func (p *uaPicker) pick() string {
	if !p.rotate {
		return userAgent
	}
	i := p.n.Add(1) - 1
	return rotatedUserAgents[int(i)%len(rotatedUserAgents)]
}

var (
	callbackDomain string
	concurrency    = defaultConcurr
	timeout        = defaultTimeout
	insecureTLS    = true
	outputFile     = defaultOutput
	proxyURL       string
	verbose        bool
	userAgent      = defaultUserAgent
	rotateUA       bool
	delay          time.Duration

	green  = color.New(color.FgHiGreen, color.Bold)
	yellow = color.New(color.FgHiYellow)
	cyan   = color.New(color.FgHiCyan)
)

func main() {
	flag.StringVar(&callbackDomain, "callback", "", "callback host used to replace FUZZ, e.g. http://abc123.oastify.com (required)")
	flag.IntVar(&concurrency, "c", defaultConcurr, "number of concurrent workers")
	flag.DurationVar(&timeout, "timeout", defaultTimeout, "per-request timeout")
	flag.BoolVar(&insecureTLS, "insecure", true, "skip TLS certificate verification")
	flag.StringVar(&outputFile, "output", defaultOutput, "file to append vulnerable URLs to")
	flag.StringVar(&proxyURL, "proxy", "", "HTTP(S) proxy, e.g. http://127.0.0.1:8080")
	flag.BoolVar(&verbose, "v", false, "verbose output for every request")
	flag.StringVar(&userAgent, "ua", defaultUserAgent, "User-Agent header to send")
	flag.BoolVar(&rotateUA, "rotate-ua", false, "rotate User-Agent per request from a list of current browsers")
	flag.DurationVar(&delay, "delay", 0, "delay between requests per worker, e.g. 500ms")
	flag.Parse()

	if callbackDomain == "" {
		fmt.Fprintln(os.Stderr, "error: -callback is required, e.g. -callback http://abc123.oastify.com")
		flag.Usage()
		os.Exit(1)
	}
	if !strings.Contains(callbackDomain, "://") {
		callbackDomain = "http://" + callbackDomain
	}
	cb, err := url.Parse(callbackDomain)
	if err != nil || cb.Hostname() == "" {
		fmt.Fprintf(os.Stderr, "error: invalid -callback value: %s\n", callbackDomain)
		os.Exit(1)
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if !resolves(context.Background(), cb.Hostname()) {
		fmt.Fprintf(os.Stderr, "error: callback host %s does not resolve, check your -callback value\n", cb.Hostname())
		os.Exit(1)
	}

	client := newClient()

	var input io.Reader = os.Stdin
	if flag.NArg() > 0 {
		file, err := os.Open(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open file: %s\n", err)
			os.Exit(1)
		}
		defer file.Close()
		input = file
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	out, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open output file: %s\n", err)
		os.Exit(1)
	}

	urls := make(chan string)
	var wg sync.WaitGroup
	var tested, found atomic.Int64
	picker := &uaPicker{rotate: rotateUA}
	wg.Add(concurrency)
	for range concurrency {
		go func() {
			defer wg.Done()
			worker(ctx, client, cb, picker, urls, out, &tested, &found)
		}()
	}

	go func() {
		sc := bufio.NewScanner(input)
		seen := make(map[string]bool)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || seen[line] {
				continue
			}
			seen[line] = true
			select {
			case urls <- line:
			case <-ctx.Done():
				return
			}
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "input error: %s\n", err)
		}
		close(urls)
	}()

	wg.Wait()
	_ = out.Close() // explicit so the exit code below cannot skip it
	green.Printf("[*] done: %d tested, %d vulnerable — results in %s\n", tested.Load(), found.Load(), outputFile)
	if found.Load() > 0 {
		// Non-zero exit when findings exist, so pipelines can react.
		os.Exit(1)
	}
}

func worker(ctx context.Context, client *http.Client, cb *url.URL, picker *uaPicker, urls <-chan string, out *os.File, tested, found *atomic.Int64) {
	for raw := range urls {
		select {
		case <-ctx.Done():
			return
		default:
		}

		u, err := url.ParseRequestURI(raw)
		if err != nil {
			yellow.Fprintf(os.Stderr, "[!] invalid url: %s\n", raw)
			continue
		}
		if !strings.Contains(u.String(), "FUZZ") {
			yellow.Fprintf(os.Stderr, "[!] no FUZZ placeholder: %s\n", u)
			continue
		}

		testURL := strings.Replace(u.String(), "FUZZ", cb.String(), 1)

		body, status, err := fetch(ctx, client, testURL, picker.pick())
		if err != nil {
			if verbose {
				yellow.Fprintf(os.Stderr, "[!] failed: %s (%s)\n", testURL, err)
			}
			continue
		}
		tested.Add(1)
		if verbose {
			cyan.Fprintf(os.Stderr, "[*] %s -> %s\n", testURL, status)
		}

		// Detection: the target application echoes the callback URL back in
		// its response, proving the server-side request was made.
		if strings.Contains(body, cb.Hostname()) {
			found.Add(1)
			green.Printf("[*] Vulnerable System Found! [*] %s\n", u)
			if _, err := fmt.Fprintln(out, u.String()); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write result: %s\n", err)
			}
		}

		if delay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}
}

func newClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecureTLS}, // #nosec G402 - intentional, controlled by -insecure
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: defaultTimeout,
	}
	if proxyURL != "" {
		pu, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid -proxy value: %s\n", err)
			os.Exit(1)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// The callback endpoint may redirect; do not follow it.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func fetch(ctx context.Context, client *http.Client, target, ua string) (string, string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap at 1 MiB
	if err != nil {
		return "", resp.Status, err
	}
	return string(body), resp.Status, nil
}

func resolves(ctx context.Context, host string) bool {
	r := &net.Resolver{}
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(lookupCtx, host)
	return err == nil && len(addrs) > 0
}
