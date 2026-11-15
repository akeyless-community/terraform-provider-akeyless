package akeyless

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var (
	providerRetryBlock = map[string]interface{}{
		"error_message_regex":  []interface{}{"Too Many Requests"},
		"interval_seconds":     5,
		"max_interval_seconds": 5,
		"max_retries":          1,
	}
	resourceRetryBlock = map[string]interface{}{
		"error_message_regex":  []interface{}{"Too Many Requests"},
		"interval_seconds":     2,
		"max_interval_seconds": 3,
		"max_retries":          3,
	}
)

func TestRetryDefaultIsMaster(t *testing.T) {
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

	calls, err := runResourceOp(t, nil, nil, 10, "429 Too Many Requests")
	if err == nil || calls != 1 {
		t.Errorf("calls=%d err=%v want 1 call without any retry block", calls, err)
	}
}

func TestRetryProviderBlock(t *testing.T) {
	d := schema.TestResourceDataRaw(t, Provider().Schema, map[string]interface{}{
		"retry": []interface{}{providerRetryBlock},
	})
	cfg, err := retryConfigFromData(d)
	if err != nil || cfg == nil {
		t.Fatalf("cfg=%v err=%v", cfg, err)
	}
	if cfg.maxRetries != 1 || cfg.interval != 5*time.Second {
		t.Errorf("cfg=%+v", cfg)
	}

	empty := schema.TestResourceDataRaw(t, Provider().Schema, map[string]interface{}{})
	if cfg, err := retryConfigFromData(empty); cfg != nil || err != nil {
		t.Errorf("cfg=%v err=%v want nil without a provider retry block", cfg, err)
	}
}

func TestRetryResource(t *testing.T) {
	waits := captureWaits(t)

	t.Run("matching error reruns until success", func(t *testing.T) {
		*waits = nil
		calls, err := runResourceOp(t, nil, resourceRetryBlock, 2, "429 Too Many Requests")
		if err != nil || calls != 3 {
			t.Errorf("calls=%d err=%v want 3 calls and success", calls, err)
		}
		if len(*waits) != 2 || (*waits)[0] != 2*time.Second || (*waits)[1] != 3*time.Second {
			t.Errorf("waits=%v want [2s 3s]", *waits)
		}
	})

	t.Run("gives up after max_retries", func(t *testing.T) {
		calls, err := runResourceOp(t, nil, resourceRetryBlock, 10, "429 Too Many Requests")
		if err == nil || calls != 4 {
			t.Errorf("calls=%d err=%v want 4 calls and error", calls, err)
		}
	})

	t.Run("non-matching error not rerun", func(t *testing.T) {
		calls, err := runResourceOp(t, nil, resourceRetryBlock, 10, "item not found")
		if err == nil || calls != 1 {
			t.Errorf("calls=%d err=%v want 1 call", calls, err)
		}
	})
}

func TestRetryProviderDefaultAndOverride(t *testing.T) {
	waits := captureWaits(t)
	providerCfg := providerRetryConfig(t)

	t.Run("provider block applies to a resource without retry", func(t *testing.T) {
		*waits = nil
		calls, err := runResourceOp(t, providerCfg, nil, 1, "429 Too Many Requests")
		if err != nil || calls != 2 {
			t.Errorf("calls=%d err=%v want 2 calls and success", calls, err)
		}
		if len(*waits) != 1 || (*waits)[0] != 5*time.Second {
			t.Errorf("waits=%v want [5s] from the provider block", *waits)
		}
	})

	t.Run("resource block wins over provider block", func(t *testing.T) {
		*waits = nil
		calls, err := runResourceOp(t, providerCfg, resourceRetryBlock, 2, "429 Too Many Requests")
		if err != nil || calls != 3 {
			t.Errorf("calls=%d err=%v want 3 calls and success", calls, err)
		}
		if len(*waits) != 2 || (*waits)[0] != 2*time.Second || (*waits)[1] != 3*time.Second {
			t.Errorf("waits=%v want [2s 3s] from the resource block only", *waits)
		}
	})

	t.Run("resource max_retries 0 disables the provider default", func(t *testing.T) {
		noRetry := map[string]interface{}{
			"error_message_regex":  []interface{}{"Too Many Requests"},
			"interval_seconds":     1,
			"max_interval_seconds": 1,
			"max_retries":          0,
		}
		calls, err := runResourceOp(t, providerCfg, noRetry, 10, "429 Too Many Requests")
		if err == nil || calls != 1 {
			t.Errorf("calls=%d err=%v want 1 call", calls, err)
		}
	})
}

func TestRetryCancelStopsWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := sleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("err=%v want context.Canceled", err)
	}
	if time.Since(start) > time.Second {
		t.Error("wait was not stopped")
	}
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

func captureWaits(t *testing.T) *[]time.Duration {
	t.Helper()
	restore := retrySleep
	waits := &[]time.Duration{}
	retrySleep = func(_ context.Context, d time.Duration) error {
		*waits = append(*waits, d)
		return nil
	}
	t.Cleanup(func() { retrySleep = restore })
	return waits
}

func providerRetryConfig(t *testing.T) *retryConfig {
	t.Helper()
	d := schema.TestResourceDataRaw(t, Provider().Schema, map[string]interface{}{
		"retry": []interface{}{providerRetryBlock},
	})
	cfg, err := retryConfigFromData(d)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// runResourceOp wraps a Create that fails failCount times with errMsg, then succeeds.
func runResourceOp(t *testing.T, providerCfg *retryConfig, retry map[string]interface{}, failCount int, errMsg string) (int, error) {
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
	err := r.Create(d, &providerMeta{retry: providerCfg})
	return calls, err
}
