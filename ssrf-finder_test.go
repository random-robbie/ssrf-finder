package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// runWorker feeds lines to a single worker and returns the contents of the
// output file, exercising the same pipeline main() uses.
func runWorker(t *testing.T, lines []string) string {
	t.Helper()

	outPath := filepath.Join(t.TempDir(), "ssrf.log")
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create output: %s", err)
	}
	defer out.Close()

	cbURL, err := url.Parse("http://callback.example/oast")
	if err != nil {
		t.Fatalf("parse callback: %s", err)
	}

	urls := make(chan string)
	done := make(chan struct{})
	go func() {
		worker(context.Background(), newClient(), cbURL, urls, out, &atomic.Int64{}, &atomic.Int64{})
		close(done)
	}()
	for _, l := range lines {
		urls <- l
	}
	close(urls)
	<-done

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %s", err)
	}
	return string(data)
}

func TestDetectsReflectedCallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable target: echoes the requested URL (including the
		// substituted callback host) back in the body.
		_, _ = w.Write([]byte("fetched " + r.URL.String() + " ok"))
	}))
	defer srv.Close()

	got := runWorker(t, []string{srv.URL + "/fetch?url=FUZZ"})
	if !strings.Contains(got, "/fetch?url=FUZZ") {
		t.Errorf("expected vulnerable URL with FUZZ placeholder in output, got %q", got)
	}
}

func TestSafeTargetNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("nothing to see here"))
	}))
	defer srv.Close()

	got := runWorker(t, []string{srv.URL + "/fetch?url=FUZZ"})
	if got != "" {
		t.Errorf("safe target should not be logged, got %q", got)
	}
}

func TestErrorTargetNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	got := runWorker(t, []string{srv.URL + "/fetch?url=FUZZ"})
	if got != "" {
		t.Errorf("500 target should not be logged, got %q", got)
	}
}

func TestNonEchoingCallbackValueNotFlagged(t *testing.T) {
	// A target that fetches the callback but never reflects its content must
	// not be flagged: the reflection check alone cannot prove this case.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("done"))
	}))
	defer srv.Close()

	got := runWorker(t, []string{srv.URL + "/fetch?url=FUZZ"})
	if got != "" {
		t.Errorf("non-reflecting target should not be logged, got %q", got)
	}
}

func TestFuzzSubstitution(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		_, _ = w.Write([]byte("hit " + gotPath))
	}))
	defer srv.Close()

	runWorker(t, []string{srv.URL + "/fetch?url=FUZZ&x=1"})
	if !strings.Contains(gotPath, "callback.example") {
		t.Errorf("FUZZ should be replaced with the callback URL, request path was %q", gotPath)
	}
	if strings.Contains(gotPath, "FUZZ") {
		t.Errorf("FUZZ should not survive substitution, request path was %q", gotPath)
	}
}

func TestInvalidAndMissingFuzzLinesSkipped(t *testing.T) {
	got := runWorker(t, []string{"not-a-url", "http://no-fuzz-here.example/one"})
	if got != "" {
		t.Errorf("invalid input should not produce findings, got %q", got)
	}
}
