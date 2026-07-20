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

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// --- Transport tests ---

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

	rt := newRetryTransport(http.DefaultTransport, cfg)
	var slept time.Duration
	rt.sleep = func(ctx context.Context, d time.Duration) error {
		slept += d
		return nil
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
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
		t.Fatalf("expected sleep from body release delay, got %s", slept)
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
	if atomic.LoadInt32(&hits) != 3 {
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

func TestParseReleaseDelaySeconds(t *testing.T) {
	sec, ok := parseReleaseDelaySeconds(`Message: will be released in 14.148893476s`)
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

// --- Resource retry tests ---

func resourceWithRetrySchema() *schema.Resource {
	r := &schema.Resource{Schema: map[string]*schema.Schema{}}
	r.Schema["retry"] = resourceRetrySchema()
	return r
}

func TestResourceRetryConfig_Absent(t *testing.T) {
	r := resourceWithRetrySchema()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{})

	_, ok, err := resourceRetryConfigFromData(d)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false when no retry block is set")
	}
}

func TestResourceRetryConfig_OverridesAndDefaults(t *testing.T) {
	r := resourceWithRetrySchema()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{
			map[string]interface{}{
				"max_retries":         5,
				"interval_seconds":    2.0,
				"max_backoff_seconds": 20.0,
				"multiplier":          3.0,
				"retry_on_messages":   []interface{}{"custom error"},
			},
		},
	})

	cfg, ok, err := resourceRetryConfigFromData(d)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true when retry block is set")
	}
	if cfg.MaxRetries != 5 || cfg.IntervalSeconds != 2.0 || cfg.MaxBackoffSeconds != 20.0 || cfg.Multiplier != 3.0 {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}
	if _, retried := cfg.RetryOnStatusCodes[429]; !retried {
		t.Fatal("expected default busy status codes to be inherited")
	}
	if len(cfg.ErrorMessageRegex) != 1 || !cfg.ErrorMessageRegex[0].MatchString("a custom error b") {
		t.Fatalf("retry_on_messages not compiled: %+v", cfg.ErrorMessageRegex)
	}
}

func TestResourceRetryConfig_StatusCodesOverride(t *testing.T) {
	r := resourceWithRetrySchema()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{
			map[string]interface{}{
				"retry_on_status_codes": []interface{}{429, 503},
			},
		},
	})

	cfg, ok, err := resourceRetryConfigFromData(d)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if _, ok := cfg.RetryOnStatusCodes[429]; !ok {
		t.Fatal("expected 429")
	}
	if _, ok := cfg.RetryOnStatusCodes[503]; !ok {
		t.Fatal("expected 503")
	}
	if _, ok := cfg.RetryOnStatusCodes[500]; ok {
		t.Fatal("500 should not be present when overridden")
	}
}

func TestResourceRetryConfig_InvalidRegexErrors(t *testing.T) {
	r := resourceWithRetrySchema()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{
			map[string]interface{}{
				"retry_on_messages": []interface{}{"("},
			},
		},
	})

	if _, _, err := resourceRetryConfigFromData(d); err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestResourceRetryDeps_SwapsClientOnlyWhenConfigured(t *testing.T) {
	r := resourceWithRetrySchema()
	pm := &providerMeta{apiGwAddress: "https://api.example.com"}

	noRetry := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{})
	got, err := resourceRetryDeps(noRetry, pm)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != interface{}(pm) {
		t.Fatal("expected unchanged meta when no retry block")
	}

	withRetry := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{map[string]interface{}{"max_retries": 1}},
	})
	got, err = resourceRetryDeps(withRetry, pm)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	cp, ok := got.(*providerMeta)
	if !ok || cp == pm {
		t.Fatal("expected a distinct providerMeta copy")
	}
	if cp.client == nil {
		t.Fatal("expected a resource retry client to be built")
	}
}
