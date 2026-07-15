package akeyless

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testRetryTransport(cfg retryConfig) *retryTransport {
	rt := newRetryTransport(http.DefaultTransport, cfg)
	rt.sleep = func(ctx context.Context, d time.Duration) error { return nil }
	return rt
}

func TestRetryTransport_DefaultRetriesHTTP429(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`Too Many Requests`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	cfg := defaultRetryConfig()
	cfg.MaxRetries = 2
	cfg.RandomizationFactor = 0
	rt := testRetryTransport(cfg)

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("hits=%d want 2", hits)
	}
}

func TestRetryTransport_429Then200(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"Too Many Requests. Message: will be released in 0.01s"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	cfg := defaultRetryConfig()
	cfg.MaxRetries = 3
	cfg.IntervalSeconds = 0.001
	cfg.MaxBackoffSeconds = 1
	cfg.RandomizationFactor = 0

	rt := newRetryTransport(http.DefaultTransport, cfg)
	var slept time.Duration
	rt.sleep = func(ctx context.Context, d time.Duration) error {
		slept += d
		return nil
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("hits=%d want 2", hits)
	}
	if slept <= 0 {
		t.Fatalf("expected sleep from release hint, got %s", slept)
	}
}

func TestRetryTransport_RetryAfterHeader(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`rate limited`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultRetryConfig()
	cfg.MaxRetries = 2
	cfg.MaxBackoffSeconds = 30
	rt := newRetryTransport(http.DefaultTransport, cfg)
	var slept time.Duration
	rt.sleep = func(ctx context.Context, d time.Duration) error {
		slept = d
		return nil
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if slept != 2*time.Second {
		t.Fatalf("slept=%s want 2s", slept)
	}
}

func TestRetryTransport_Wrapped429In403Body(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`Desc: Failed to describe permissions data. Status 429 Too Many Requests. Message: will be released in 0.01s`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultRetryConfig()
	cfg.MaxRetries = 2
	cfg.RandomizationFactor = 0
	rt := testRetryTransport(cfg)

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("hits=%d", hits)
	}
}

func TestRetryTransport_Plain403NoRetry(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"access denied"}`))
	}))
	defer srv.Close()

	cfg := defaultRetryConfig()
	cfg.MaxRetries = 3
	rt := newRetryTransport(http.DefaultTransport, cfg)
	rt.sleep = func(ctx context.Context, d time.Duration) error {
		t.Fatal("should not sleep")
		return nil
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("hits=%d want 1", hits)
	}
}

func TestRetryTransport_401NoRetry(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`unauthorized`))
	}))
	defer srv.Close()

	cfg := defaultRetryConfig()
	cfg.MaxRetries = 3
	rt := newRetryTransport(http.DefaultTransport, cfg)
	rt.sleep = func(ctx context.Context, d time.Duration) error {
		t.Fatal("should not sleep")
		return nil
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("hits=%d", hits)
	}
}

func TestRetryTransport_MaxRetriesExhausted(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`Too Many Requests`))
	}))
	defer srv.Close()

	cfg := defaultRetryConfig()
	cfg.MaxRetries = 2
	cfg.RandomizationFactor = 0
	cfg.IntervalSeconds = 0.001
	rt := testRetryTransport(cfg)

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if atomic.LoadInt32(&hits) != 3 { // 1 initial + 2 retries
		t.Fatalf("hits=%d want 3", hits)
	}
}

func TestRetryTransport_ContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`Too Many Requests`))
	}))
	defer srv.Close()

	cfg := defaultRetryConfig()
	cfg.MaxRetries = 5
	rt := newRetryTransport(http.DefaultTransport, cfg)
	rt.sleep = func(ctx context.Context, d time.Duration) error {
		return context.Canceled
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	_, err := rt.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error")
	}
	if err != context.Canceled {
		t.Fatalf("err=%v", err)
	}
}

func TestRetryTransport_ErrorMessageRegex(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`temporary conflict please retry`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultRetryConfig()
	cfg.MaxRetries = 2
	cfg.RandomizationFactor = 0
	cfg.ErrorMessageRegex = mustCompileRegexes(t, []string{"temporary conflict"})
	rt := testRetryTransport(cfg)

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("status=%d hits=%d", resp.StatusCode, hits)
	}
}

func TestRetryTransport_500Retry(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`boom`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultRetryConfig()
	cfg.MaxRetries = 1
	cfg.RandomizationFactor = 0
	rt := testRetryTransport(cfg)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{"a":1}`))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("hits=%d", hits)
	}
}

func TestParseReleaseHintSeconds(t *testing.T) {
	sec, ok := parseReleaseHintSeconds(`Message: will be released in 14.148893476s`)
	if !ok || sec < 14 || sec > 15 {
		t.Fatalf("sec=%v ok=%v", sec, ok)
	}
}

func mustCompileRegexes(t *testing.T, patterns []string) []*regexp.Regexp {
	t.Helper()
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, re)
	}
	return out
}
