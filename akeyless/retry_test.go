package akeyless

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// --- Retry behavior tests ---

func TestRetry(t *testing.T) {
	t.Run("429 retried until success", func(t *testing.T) {
		hits := runRetry(t, 3, 3) // fail 3 times, allow 3 retries
		if hits != 4 {
			t.Errorf("hits=%d want 4", hits)
		}
	})

	t.Run("gives up after max retries", func(t *testing.T) {
		hits := runRetry(t, 5, 2) // fail 5 times, allow only 2 retries
		if hits != 3 {
			t.Errorf("hits=%d want 3 (1 initial + 2 retries)", hits)
		}
	})

	t.Run("401 not retried", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		resp := doRequest(t, srv.URL, defaultRetryConfig())
		if resp.StatusCode != 401 {
			t.Errorf("401 should not retry")
		}
	})

	t.Run("rate limit in body triggers retry", func(t *testing.T) {
		var hits int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&hits, 1) == 1 {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`will be released in 0.01s`))
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		resp := doRequest(t, srv.URL, defaultRetryConfig())
		if resp.StatusCode != 200 || hits != 2 {
			t.Errorf("body rate-limit not retried: status=%d hits=%d", resp.StatusCode, hits)
		}
	})
}

// --- Provider vs Resource tests ---

func TestProviderRetry(t *testing.T) {
	hits := runRetry(t, 2, 2) // provider default-like config
	if hits != 3 {
		t.Errorf("provider retry failed: hits=%d want 3", hits)
	}
}

func TestResourceRetry(t *testing.T) {
	d := testResourceData(t, map[string]interface{}{"max_retries": 2})
	cfg, ok, _ := resourceRetryConfigFromData(d)
	if !ok {
		t.Fatal("expected config")
	}
	if cfg.MaxRetries != 2 {
		t.Errorf("MaxRetries=%d want 2", cfg.MaxRetries)
	}
}

func TestResourceWinsOverProvider(t *testing.T) {
	// Provider: max_retries=1 (not enough for 2 failures)
	// Resource: max_retries=3 (enough)
	
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Provider fails (max_retries=1)
	providerCfg := defaultRetryConfig()
	providerCfg.MaxRetries = 1
	resp := doRequest(t, srv.URL, providerCfg)
	if resp.StatusCode != 429 {
		t.Fatalf("provider should fail: status=%d", resp.StatusCode)
	}

	atomic.StoreInt32(&hits, 0)

	// Resource succeeds (max_retries=3)
	resourceCfg := defaultRetryConfig()
	resourceCfg.MaxRetries = 3
	resp = doRequest(t, srv.URL, resourceCfg)
	if resp.StatusCode != 200 {
		t.Errorf("resource should succeed: status=%d", resp.StatusCode)
	}
}

// --- Config parsing tests ---

func TestResourceRetryConfig(t *testing.T) {
	t.Run("absent returns false", func(t *testing.T) {
		_, ok, _ := resourceRetryConfigFromData(testResourceData(t, nil))
		if ok {
			t.Error("expected ok=false")
		}
	})

	t.Run("parses fields", func(t *testing.T) {
		cfg, ok, _ := resourceRetryConfigFromData(testResourceData(t, map[string]interface{}{
			"max_retries":           5,
			"retry_on_status_codes": []interface{}{429, 503},
		}))
		if !ok || cfg.MaxRetries != 5 {
			t.Errorf("MaxRetries=%d ok=%v", cfg.MaxRetries, ok)
		}
		if _, has := cfg.RetryOnStatusCodes[503]; !has {
			t.Error("missing 503")
		}
	})

	t.Run("invalid regex errors", func(t *testing.T) {
		_, _, err := resourceRetryConfigFromData(testResourceData(t, map[string]interface{}{
			"retry_on_messages": []interface{}{"("},
		}))
		if err == nil {
			t.Error("expected error")
		}
	})
}

// --- Client swap test ---

func TestResourceRetryDeps(t *testing.T) {
	pm := &providerMeta{apiGwAddress: "https://example.com"}

	// No retry block → same meta
	got, _ := resourceRetryDeps(testResourceData(t, nil), pm)
	if got != pm {
		t.Error("expected same meta")
	}

	// With retry block → new client
	got, _ = resourceRetryDeps(testResourceData(t, map[string]interface{}{"max_retries": 5}), pm)
	if got == pm {
		t.Error("expected new meta")
	}
}

// --- Helpers ---

func runRetry(t *testing.T, failCount, maxRetries int) int32 {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if int(atomic.AddInt32(&hits, 1)) <= failCount {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultRetryConfig()
	cfg.MaxRetries = maxRetries
	doRequest(t, srv.URL, cfg)
	return atomic.LoadInt32(&hits)
}

func doRequest(t *testing.T, url string, cfg retryConfig) *http.Response {
	t.Helper()
	rt := newRetryTransport(http.DefaultTransport, cfg)
	rt.sleep = func(context.Context, time.Duration) error { return nil }
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func testResourceData(t *testing.T, retry map[string]interface{}) *schema.ResourceData {
	t.Helper()
	r := &schema.Resource{Schema: map[string]*schema.Schema{"retry": resourceRetrySchema()}}
	raw := map[string]interface{}{}
	if retry != nil {
		raw["retry"] = []interface{}{retry}
	}
	return schema.TestResourceDataRaw(t, r.Schema, raw)
}
