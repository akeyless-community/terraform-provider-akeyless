package akeyless

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// --- Provider level: maximum_busy_retry_attempts ---

func TestRetryProviderDefaultIsMaster(t *testing.T) {
	d := schema.TestResourceDataRaw(t, Provider().Schema, map[string]interface{}{})
	if got := d.Get("maximum_busy_retry_attempts").(int); got != 0 {
		t.Fatalf("maximum_busy_retry_attempts=%d want 0", got)
	}

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client := &http.Client{Transport: &retryTransport{base: http.DefaultTransport, retries: 3}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 || hits != 1 {
		t.Errorf("status=%d hits=%d want 429 and 1 hit", resp.StatusCode, hits)
	}
}

func TestRetryProviderEnv(t *testing.T) {
	t.Setenv("AKEYLESS_MAXIMUM_BUSY_RETRY_ATTEMPTS", "5")
	d := schema.TestResourceDataRaw(t, Provider().Schema, map[string]interface{}{})
	if got := d.Get("maximum_busy_retry_attempts").(int); got != 5 {
		t.Errorf("maximum_busy_retry_attempts=%d want 5", got)
	}
}

func TestRetryBusyTransport(t *testing.T) {
	t.Run("429 retried until success", func(t *testing.T) {
		hits, waits, resp := runBusy(t, 3, func(hit int32, w http.ResponseWriter) {
			if hit <= 2 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
		if resp.StatusCode != 200 || hits != 3 || len(waits) != 2 {
			t.Errorf("status=%d hits=%d waits=%v", resp.StatusCode, hits, waits)
		}
		if waits[0] != time.Second || waits[1] != 2*time.Second {
			t.Errorf("waits=%v want [1s 2s]", waits)
		}
	})

	t.Run("gives up after max attempts", func(t *testing.T) {
		hits, waits, resp := runBusy(t, 2, func(_ int32, w http.ResponseWriter) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		if resp.StatusCode != 503 || hits != 3 || len(waits) != 2 {
			t.Errorf("status=%d hits=%d waits=%d, want 503, 3 hits, one wait per retry", resp.StatusCode, hits, len(waits))
		}
	})

	t.Run("Retry-After is used", func(t *testing.T) {
		_, waits, _ := runBusy(t, 1, func(hit int32, w http.ResponseWriter) {
			if hit == 1 {
				w.Header().Set("Retry-After", "7")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
		if len(waits) != 1 || waits[0] != 7*time.Second {
			t.Errorf("waits=%v want [7s]", waits)
		}
	})

	t.Run("wrapped rate-limit body is retried with its release delay", func(t *testing.T) {
		hits, waits, resp := runBusy(t, 1, func(hit int32, w http.ResponseWriter) {
			if hit == 1 {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`429 Too Many Requests: will be released in 4.5s`))
				return
			}
			w.WriteHeader(http.StatusOK)
		})
		if resp.StatusCode != 200 || hits != 2 || len(waits) != 1 || waits[0] != 4500*time.Millisecond {
			t.Errorf("status=%d hits=%d waits=%v", resp.StatusCode, hits, waits)
		}
	})

	t.Run("401 and plain 403 not retried", func(t *testing.T) {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
			hits, _, resp := runBusy(t, 3, func(_ int32, w http.ResponseWriter) {
				w.WriteHeader(status)
			})
			if resp.StatusCode != status || hits != 1 {
				t.Errorf("status=%d hits=%d want 1 hit", resp.StatusCode, hits)
			}
		}
	})

	t.Run("cancel stops the wait", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		if err := sleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
			t.Errorf("err=%v want context.Canceled", err)
		}
		if time.Since(start) > time.Second {
			t.Error("wait was not stopped")
		}
	})

	t.Run("request body is resent", func(t *testing.T) {
		var bodies []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			bodies = append(bodies, string(b))
			if len(bodies) == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		rt := newBusyRetryTransport(http.DefaultTransport, 1)
		rt.sleep = func(context.Context, time.Duration) error { return nil }
		req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{"name":"x"}`))
		if _, err := rt.RoundTrip(req); err != nil {
			t.Fatal(err)
		}
		if len(bodies) != 2 || bodies[1] != `{"name":"x"}` {
			t.Errorf("bodies=%v", bodies)
		}
	})
}

// --- Resource level: retry {} ---

func TestRetryResource(t *testing.T) {
	restore := resourceRetrySleep
	var waits []time.Duration
	resourceRetrySleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	defer func() { resourceRetrySleep = restore }()

	retryBlock := map[string]interface{}{
		"error_message_regex":  []interface{}{"Too Many Requests"},
		"interval_seconds":     2,
		"max_interval_seconds": 3,
		"max_retries":          3,
	}

	t.Run("matching error reruns until success", func(t *testing.T) {
		waits = nil
		calls, err := runResourceOp(t, retryBlock, 2, "429 Too Many Requests")
		if err != nil || calls != 3 {
			t.Errorf("calls=%d err=%v want 3 calls and success", calls, err)
		}
		if len(waits) != 2 || waits[0] != 2*time.Second || waits[1] != 3*time.Second {
			t.Errorf("waits=%v want [2s 3s]", waits)
		}
	})

	t.Run("gives up after max_retries", func(t *testing.T) {
		calls, err := runResourceOp(t, retryBlock, 10, "429 Too Many Requests")
		if err == nil || calls != 4 {
			t.Errorf("calls=%d err=%v want 4 calls and error", calls, err)
		}
	})

	t.Run("non-matching error not rerun", func(t *testing.T) {
		calls, err := runResourceOp(t, retryBlock, 10, "item not found")
		if err == nil || calls != 1 {
			t.Errorf("calls=%d err=%v want 1 call", calls, err)
		}
	})

	t.Run("no retry block runs once", func(t *testing.T) {
		calls, err := runResourceOp(t, nil, 10, "429 Too Many Requests")
		if err == nil || calls != 1 {
			t.Errorf("calls=%d err=%v want 1 call", calls, err)
		}
	})
}

func TestRetryResourceEnable(t *testing.T) {
	r := &schema.Resource{
		Schema: map[string]*schema.Schema{
			"name": {Type: schema.TypeString, Required: true, ForceNew: true},
		},
		CreateContext: func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics { return nil },
		ReadContext:   func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics { return nil },
		DeleteContext: func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics { return nil },
	}
	EnableResourceRetry(r)

	if r.Schema["retry"] == nil || r.Schema["retry"].ForceNew {
		t.Error("retry must exist and must not be ForceNew")
	}
	if r.UpdateContext == nil {
		t.Error("expected no-op Update for a resource without Update")
	}
	if err := r.InternalValidate(nil, true); err != nil {
		t.Errorf("InternalValidate: %v", err)
	}
}

func TestRetryAllResourcesValid(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatal(err)
	}
}

// --- Helpers ---

func runBusy(t *testing.T, attempts int, handler func(hit int32, w http.ResponseWriter)) (int32, []time.Duration, *http.Response) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(atomic.AddInt32(&hits, 1), w)
	}))
	defer srv.Close()

	var waits []time.Duration
	rt := newBusyRetryTransport(&retryTransport{base: http.DefaultTransport, retries: 3}, attempts)
	rt.sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	return atomic.LoadInt32(&hits), waits, resp
}

// runResourceOp wraps a Create that fails failCount times with errMsg, then succeeds.
func runResourceOp(t *testing.T, retry map[string]interface{}, failCount int, errMsg string) (int, error) {
	t.Helper()
	calls := 0
	r := &schema.Resource{
		Schema: map[string]*schema.Schema{},
		Create: func(*schema.ResourceData, interface{}) error {
			calls++
			if calls <= failCount {
				return errors.New(errMsg)
			}
			return nil
		},
	}
	EnableResourceRetry(r)

	raw := map[string]interface{}{}
	if retry != nil {
		raw["retry"] = []interface{}{retry}
	}
	d := schema.TestResourceDataRaw(t, r.Schema, raw)
	err := r.Create(d, nil)
	return calls, err
}
