package akeyless

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
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

func TestRetryStatusCodes(t *testing.T) {
	captureWaits(t)
	codesBlock := map[string]interface{}{
		"retry_on_status_codes": []interface{}{429, 503},
		"interval_seconds":      1,
		"max_interval_seconds":  1,
		"max_retries":           3,
	}

	t.Run("listed status is retried", func(t *testing.T) {
		calls, err := runResourceOpErr(t, nil, codesBlock, 2, func() error { return apiError(503, "") })
		if err != nil || calls != 3 {
			t.Errorf("calls=%d err=%v want 3 calls and success", calls, err)
		}
	})

	t.Run("other status is not retried", func(t *testing.T) {
		calls, err := runResourceOpErr(t, nil, codesBlock, 10, func() error { return apiError(404, "") })
		if err == nil || calls != 1 {
			t.Errorf("calls=%d err=%v want 1 call", calls, err)
		}
	})

	t.Run("error message is unchanged", func(t *testing.T) {
		if got := apiError(503, "").Error(); got != "can't create item: Service Unavailable" {
			t.Errorf("message=%q", got)
		}
	})
}

func TestRetryStatusCodeSurvivesDiagnostics(t *testing.T) {
	waits := captureWaits(t)
	calls := 0
	r := &schema.Resource{
		Schema: map[string]*schema.Schema{},
		CreateContext: func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
			calls++
			if calls == 1 {
				return common.DiagnosticsFromErr(apiError(http.StatusTooManyRequests, "15"))
			}
			return nil
		},
	}
	EnableResourceRetry(r)
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{map[string]interface{}{
			"retry_on_status_codes": []interface{}{http.StatusTooManyRequests},
			"interval_seconds":      2,
			"max_interval_seconds":  60,
			"max_retries":           1,
		}},
	})

	if diags := r.CreateContext(context.Background(), d, nil); diags.HasError() {
		t.Fatal(diags)
	}
	if calls != 2 {
		t.Errorf("calls=%d want 2", calls)
	}
	if len(*waits) != 1 || (*waits)[0] != 15*time.Second {
		t.Errorf("waits=%v want [15s] from Retry-After", *waits)
	}
}

func TestRetryDiagnosticsDetailIsMatched(t *testing.T) {
	calls := 0
	r := &schema.Resource{
		Schema: map[string]*schema.Schema{},
		CreateContext: func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
			calls++
			if calls == 1 {
				return diag.Diagnostics{{Severity: diag.Error, Summary: "can't create role", Detail: "temporarily unavailable"}}
			}
			return nil
		},
	}
	EnableResourceRetry(r)
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{map[string]interface{}{
			"error_message_regex": []interface{}{"temporarily unavailable"},
			"max_retries":         1,
		}},
	})

	if diags := r.CreateContext(context.Background(), d, nil); diags.HasError() {
		t.Fatal(diags)
	}
	if calls != 2 {
		t.Errorf("calls=%d want 2", calls)
	}
}

func TestRetryMetadataIsNotReturned(t *testing.T) {
	r := &schema.Resource{
		Schema: map[string]*schema.Schema{},
		CreateContext: func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
			return common.DiagnosticsFromErr(apiError(http.StatusTooManyRequests, "15"))
		},
	}
	EnableResourceRetry(r)
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{map[string]interface{}{
			"retry_on_status_codes": []interface{}{http.StatusTooManyRequests},
			"max_retries":           0,
		}},
	})

	diags := r.CreateContext(context.Background(), d, nil)
	if !diags.HasError() || diags[0].Detail != "" {
		t.Errorf("diags=%v want original error without retry metadata", diags)
	}
}

func TestRetryAfter(t *testing.T) {
	waits := captureWaits(t)
	block := map[string]interface{}{
		"retry_on_status_codes": []interface{}{429},
		"error_message_regex":   []interface{}{"will be released in"},
		"interval_seconds":      2,
		"max_interval_seconds":  60,
		"max_retries":           1,
	}

	cases := []struct {
		name string
		err  error
		want time.Duration
	}{
		{"no Retry-After uses backoff", apiError(429, ""), 2 * time.Second},
		{"longer Retry-After wins", apiError(429, "15"), 15 * time.Second},
		{"shorter Retry-After keeps backoff", apiError(429, "1"), 2 * time.Second},
		{"Retry-After is capped", apiError(429, "300"), 60 * time.Second},
		{"release delay in message", errors.New("429 Too Many Requests: will be released in 4.5s"), 4500 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			*waits = nil
			if _, err := runResourceOpErr(t, nil, block, 1, func() error { return tc.err }); err != nil {
				t.Fatal(err)
			}
			if len(*waits) != 1 || (*waits)[0] != tc.want {
				t.Errorf("waits=%v want [%s]", *waits, tc.want)
			}
		})
	}
}

func TestRetryCancelStopsRetry(t *testing.T) {
	calls := 0
	r := &schema.Resource{
		Schema: map[string]*schema.Schema{},
		Create: func(*schema.ResourceData, interface{}) error {
			calls++
			return errors.New("429 Too Many Requests")
		},
	}
	EnableResourceRetry(r)
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{"retry": []interface{}{resourceRetryBlock}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if diags := r.CreateContext(ctx, d, nil); !diags.HasError() || calls != 1 {
		t.Errorf("calls=%d diags=%v want 1 call and the error", calls, diags)
	}
	if time.Since(start) > time.Second {
		t.Error("retry wait was not stopped")
	}
}

func TestRetryOnlyRetryChangeSkipsUpdate(t *testing.T) {
	updates := 0
	r := &schema.Resource{
		Schema: map[string]*schema.Schema{
			"description": {Type: schema.TypeString, Optional: true},
		},
		Create: func(*schema.ResourceData, interface{}) error { return nil },
		Read:   func(*schema.ResourceData, interface{}) error { return nil },
		Update: func(*schema.ResourceData, interface{}) error {
			updates++
			return nil
		},
		Delete: func(*schema.ResourceData, interface{}) error { return nil },
	}
	EnableResourceRetry(r)

	state := &terraform.InstanceState{ID: "x", Attributes: map[string]string{"description": "a"}}
	run := func(raw map[string]interface{}) {
		diff, err := r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(raw), nil)
		if err != nil {
			t.Fatal(err)
		}
		d, err := schema.InternalMap(r.Schema).Data(state, diff)
		if err != nil {
			t.Fatal(err)
		}
		if diags := r.UpdateContext(context.Background(), d, nil); diags.HasError() {
			t.Fatal(diags)
		}
	}

	run(map[string]interface{}{"description": "a", "retry": []interface{}{map[string]interface{}{"retry_on_status_codes": []interface{}{429}}}})
	if updates != 0 {
		t.Errorf("updates=%d want 0 when only retry changed", updates)
	}
	run(map[string]interface{}{"description": "b"})
	if updates != 1 {
		t.Errorf("updates=%d want 1 when another field changed", updates)
	}
}

func TestRetryOnlyChangeDoesNotNeedUpdate(t *testing.T) {
	r := &schema.Resource{
		Schema: map[string]*schema.Schema{
			"description": {Type: schema.TypeString, Optional: true},
		},
		Create: func(*schema.ResourceData, interface{}) error { return nil },
		Read:   func(*schema.ResourceData, interface{}) error { return nil },
		Delete: func(*schema.ResourceData, interface{}) error { return nil },
	}
	EnableResourceRetry(r)

	state := &terraform.InstanceState{ID: "x", Attributes: map[string]string{"description": "a"}}
	run := func(raw map[string]interface{}) diag.Diagnostics {
		diff, err := r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(raw), nil)
		if err != nil {
			t.Fatal(err)
		}
		d, err := schema.InternalMap(r.Schema).Data(state, diff)
		if err != nil {
			t.Fatal(err)
		}
		return r.UpdateContext(context.Background(), d, nil)
	}

	if diags := run(map[string]interface{}{"description": "a", "retry": []interface{}{map[string]interface{}{"retry_on_status_codes": []interface{}{429}}}}); diags.HasError() {
		t.Fatalf("retry-only update returned diagnostics: %v", diags)
	}
	if diags := run(map[string]interface{}{"description": "b"}); !diags.HasError() {
		t.Fatal("expected an error for a real in-place update")
	}
}

func TestOpenAITargetRetryOnlyChange(t *testing.T) {
	r := resourceOpenAITarget()
	EnableResourceRetry(r)

	state := &terraform.InstanceState{
		ID: "/test",
		Attributes: map[string]string{
			"name":             "/test",
			"codex_oauth_mode": codexOauthModeChatGPT,
		},
	}
	_, err := r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(map[string]interface{}{
		"name":             "/test",
		"codex_oauth_mode": codexOauthModeChatGPT,
		"retry": []interface{}{map[string]interface{}{
			"error_message_regex": []interface{}{"Too Many Requests"},
		}},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRetryEmptyRegexRejected(t *testing.T) {
	r := &schema.Resource{Schema: map[string]*schema.Schema{}}
	EnableResourceRetry(r)
	cfg := terraform.NewResourceConfigRaw(map[string]interface{}{
		"retry": []interface{}{map[string]interface{}{"error_message_regex": []interface{}{""}}},
	})
	if diags := r.Validate(cfg); !diags.HasError() {
		t.Error("expected an error for an empty error_message_regex")
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

func TestRetryBlockNeedsTrigger(t *testing.T) {
	r := &schema.Resource{Schema: map[string]*schema.Schema{}}
	EnableResourceRetry(r)
	cfg := terraform.NewResourceConfigRaw(map[string]interface{}{
		"retry": []interface{}{map[string]interface{}{"max_retries": 2}},
	})
	if diags := r.Validate(cfg); !diags.HasError() {
		t.Error("expected an error for a retry block without error_message_regex or retry_on_status_codes")
	}
}

func TestRetryIntervalValidation(t *testing.T) {
	t.Run("maximum is not smaller than interval", func(t *testing.T) {
		d := schema.TestResourceDataRaw(t, Provider().Schema, map[string]interface{}{
			"retry": []interface{}{map[string]interface{}{
				"error_message_regex":  []interface{}{"Too Many Requests"},
				"interval_seconds":     10,
				"max_interval_seconds": 3,
			}},
		})
		if _, err := retryConfigFromData(d); err == nil {
			t.Error("expected an error when max_interval_seconds is smaller than interval_seconds")
		}
	})

	for _, field := range []string{"interval_seconds", "max_interval_seconds"} {
		t.Run(field+" is capped", func(t *testing.T) {
			r := &schema.Resource{Schema: map[string]*schema.Schema{}}
			EnableResourceRetry(r)
			cfg := terraform.NewResourceConfigRaw(map[string]interface{}{
				"retry": []interface{}{map[string]interface{}{
					"error_message_regex": []interface{}{"Too Many Requests"},
					field:                 maxRetryIntervalSeconds + 1,
				}},
			})
			if diags := r.Validate(cfg); !diags.HasError() {
				t.Errorf("expected an error for retry.%s above %d", field, maxRetryIntervalSeconds)
			}
		})
	}
}

func TestRetryReadNotFoundRemovesFromState(t *testing.T) {
	captureWaits(t)

	t.Run("404 removes the item from state", func(t *testing.T) {
		diags, id := runRead(t, nil, func() error { return apiError(http.StatusNotFound, "") })
		if diags.HasError() || id != "" {
			t.Errorf("diags=%v id=%q want no error and empty id", diags, id)
		}
	})

	t.Run("404 from a context read removes the item from state", func(t *testing.T) {
		r := &schema.Resource{
			Schema: map[string]*schema.Schema{},
			ReadContext: func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
				return common.DiagnosticsFromErr(apiError(http.StatusNotFound, ""))
			},
		}
		EnableResourceRetry(r)
		d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{})
		d.SetId("item")
		if diags := r.ReadContext(context.Background(), d, nil); diags.HasError() || d.Id() != "" {
			t.Errorf("diags=%v id=%q want no error and empty id", diags, d.Id())
		}
	})

	t.Run("other errors are kept", func(t *testing.T) {
		diags, id := runRead(t, nil, func() error { return apiError(http.StatusInternalServerError, "") })
		if !diags.HasError() || id != "item" {
			t.Errorf("diags=%v id=%q want an error and id kept", diags, id)
		}
	})

	t.Run("404 is retried first when the retry block lists it", func(t *testing.T) {
		retry := map[string]interface{}{
			"retry_on_status_codes": []interface{}{http.StatusNotFound},
			"interval_seconds":      1,
			"max_interval_seconds":  1,
			"max_retries":           1,
		}
		calls := 0
		diags, id := runRead(t, retry, func() error {
			calls++
			if calls == 1 {
				return apiError(http.StatusNotFound, "")
			}
			return nil
		})
		if diags.HasError() || id != "item" || calls != 2 {
			t.Errorf("diags=%v id=%q calls=%d want success on retry and id kept", diags, id, calls)
		}
	})
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
	return runResourceOpErr(t, providerCfg, retry, failCount, func() error { return errors.New(errMsg) })
}

// runRead wraps a Read that returns read() for the item "item", and returns the diagnostics and the id after it.
func runRead(t *testing.T, retry map[string]interface{}, read func() error) (diag.Diagnostics, string) {
	t.Helper()
	r := &schema.Resource{
		Schema: map[string]*schema.Schema{},
		Read:   func(*schema.ResourceData, interface{}) error { return read() },
	}
	EnableResourceRetry(r)

	raw := map[string]interface{}{}
	if retry != nil {
		raw["retry"] = []interface{}{retry}
	}
	d := schema.TestResourceDataRaw(t, r.Schema, raw)
	d.SetId("item")
	diags := r.ReadContext(context.Background(), d, &providerMeta{})
	return diags, d.Id()
}

// apiError builds the error resources return for a failed API call.
func apiError(status int, retryAfter string) error {
	resp := &http.Response{StatusCode: status, Header: http.Header{}}
	if retryAfter != "" {
		resp.Header.Set("Retry-After", retryAfter)
	}
	return common.HandleError("can't create item", resp, errors.New(http.StatusText(status)))
}

// runResourceOpErr wraps a Create that fails failCount times with newErr(), then succeeds.
func runResourceOpErr(t *testing.T, providerCfg *retryConfig, retry map[string]interface{}, failCount int, newErr func() error) (int, error) {
	t.Helper()
	calls := 0
	r := &schema.Resource{
		Schema: map[string]*schema.Schema{},
		Create: func(*schema.ResourceData, interface{}) error {
			calls++
			if calls <= failCount {
				return newErr()
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
	diags := r.CreateContext(context.Background(), d, &providerMeta{retry: providerCfg})
	return calls, diagsError(diags)
}
