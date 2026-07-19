package common

import (
	"context"
	"fmt"
	"log"
	"math"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// sdkRetryTimeout is large on purpose: we stop with max_retries inside RetryFunc,
// not with the SDK helper's timeout clock.
const sdkRetryTimeout = 24 * time.Hour

// default config values
const (
	resourceRetryDefaultIntervalSeconds    = 10.0
	resourceRetryDefaultMaxIntervalSeconds = 180.0
	resourceRetryDefaultMultiplier         = 1.5
)

// defaultResourceRetryErrorPatterns mirrors provider-level transient/rate-limit text defaults.
var defaultResourceRetryErrorPatterns = []string{
	"Too Many Requests",
	"will be released in",
	"EOF",
	"connection reset by peer",
	"connection refused",
}

// ResourceRetrySchema is the optional resource-level retry block.
// When set, it overrides provider HTTP retry for that resource's CRUD calls.
func ResourceRetrySchema() *schema.Schema {
	return &schema.Schema{
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Optional resource-level retry. When set, overrides provider HTTP retry for this resource.",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"retry_on_messages": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "Error message texts that trigger a retry. Defaults to provider transient/rate-limit messages when omitted.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				"interval_seconds": {
					Type:        schema.TypeFloat,
					Optional:    true,
					Default:     resourceRetryDefaultIntervalSeconds,
					Description: "Initial wait before the first resource-level retry (seconds).",
				},
				"max_interval_seconds": {
					Type:        schema.TypeFloat,
					Optional:    true,
					Default:     resourceRetryDefaultMaxIntervalSeconds,
					Description: "Maximum wait between resource-level retries (seconds).",
				},
				"multiplier": {
					Type:        schema.TypeFloat,
					Optional:    true,
					Default:     resourceRetryDefaultMultiplier,
					Description: "Exponential backoff multiplier.",
				},
				"max_retries": {
					Type:        schema.TypeInt,
					Optional:    true,
					Default:     3,
					Description: "Maximum resource-level retries after provider/transport retries are exhausted.",
				},
			},
		},
	}
}

// AddResourceRetrySchema merges the shared retry block into a resource schema map.
func AddResourceRetrySchema(m map[string]*schema.Schema) {
	m["retry"] = ResourceRetrySchema()
}

// NoRetryMeta returns a copy of the provider meta whose client uses the plain
// (no provider-retry) transport. The akeyless package sets it. Resource retry
// uses it so provider HTTP retry does not stack on top of resource retry.
// The default is identity, so tests and callers without a provider meta are unaffected.
var NoRetryMeta = func(providerDeps interface{}) interface{} { return providerDeps }

// EnableResourceRetry adds the resource retry schema and wraps Create/Update/Delete.
// With no retry block, CRUD runs once (unchanged).
func EnableResourceRetry(r *schema.Resource) {
	if r == nil {
		return
	}
	if r.Schema == nil {
		r.Schema = map[string]*schema.Schema{}
	}
	if _, exists := r.Schema["retry"]; !exists {
		retrySchema := ResourceRetrySchema()
		// Create-only resources (no Update) require ForceNew on every schema attribute.
		if r.Update == nil && r.UpdateContext == nil {
			retrySchema.ForceNew = true
		}
		r.Schema["retry"] = retrySchema
	}

	if r.Create != nil {
		orig := r.Create
		r.Create = func(d *schema.ResourceData, providerDeps interface{}) error {
			return RetryResourceOp(d, providerDeps, func(providerDeps interface{}) error { return orig(d, providerDeps) })
		}
	}
	if r.Update != nil {
		orig := r.Update
		r.Update = func(d *schema.ResourceData, providerDeps interface{}) error {
			return RetryResourceOp(d, providerDeps, func(providerDeps interface{}) error { return orig(d, providerDeps) })
		}
	}
	if r.Delete != nil {
		orig := r.Delete
		r.Delete = func(d *schema.ResourceData, providerDeps interface{}) error {
			return RetryResourceOp(d, providerDeps, func(providerDeps interface{}) error { return orig(d, providerDeps) })
		}
	}
	if r.CreateContext != nil {
		orig := r.CreateContext
		r.CreateContext = func(ctx context.Context, d *schema.ResourceData, providerDeps interface{}) diag.Diagnostics {
			return RetryResourceOpDiag(d, providerDeps, func(providerDeps interface{}) diag.Diagnostics { return orig(ctx, d, providerDeps) })
		}
	}
	if r.UpdateContext != nil {
		orig := r.UpdateContext
		r.UpdateContext = func(ctx context.Context, d *schema.ResourceData, providerDeps interface{}) diag.Diagnostics {
			return RetryResourceOpDiag(d, providerDeps, func(providerDeps interface{}) diag.Diagnostics { return orig(ctx, d, providerDeps) })
		}
	}
	if r.DeleteContext != nil {
		orig := r.DeleteContext
		r.DeleteContext = func(ctx context.Context, d *schema.ResourceData, providerDeps interface{}) diag.Diagnostics {
			return RetryResourceOpDiag(d, providerDeps, func(providerDeps interface{}) diag.Diagnostics { return orig(ctx, d, providerDeps) })
		}
	}
}

type resourceRetryConfig struct {
	MaxRetries         int
	IntervalSeconds    float64
	MaxIntervalSeconds float64
	Multiplier         float64
	ErrorMessageRegex  []*regexp.Regexp
}

func resourceRetryConfigFromData(d *schema.ResourceData) (*resourceRetryConfig, error) {
	raw := d.Get("retry").([]interface{})
	if len(raw) == 0 || raw[0] == nil {
		return nil, nil
	}
	m := raw[0].(map[string]interface{})

	cfg := &resourceRetryConfig{
		MaxRetries:         3,
		IntervalSeconds:    resourceRetryDefaultIntervalSeconds,
		MaxIntervalSeconds: resourceRetryDefaultMaxIntervalSeconds,
		Multiplier:         resourceRetryDefaultMultiplier,
	}
	if v, ok := m["max_retries"].(int); ok {
		cfg.MaxRetries = v
	}
	if v, ok := m["interval_seconds"].(float64); ok {
		cfg.IntervalSeconds = v
	}
	if v, ok := m["max_interval_seconds"].(float64); ok {
		cfg.MaxIntervalSeconds = v
	}
	if v, ok := m["multiplier"].(float64); ok {
		cfg.Multiplier = v
	}

	patterns, _ := m["retry_on_messages"].([]interface{})
	for _, p := range patterns {
		s, ok := p.(string)
		if !ok || s == "" {
			continue
		}
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("invalid retry.retry_on_messages %q: %w", s, err)
		}
		cfg.ErrorMessageRegex = append(cfg.ErrorMessageRegex, re)
	}
	if len(cfg.ErrorMessageRegex) == 0 {
		for _, s := range defaultResourceRetryErrorPatterns {
			cfg.ErrorMessageRegex = append(cfg.ErrorMessageRegex, regexp.MustCompile(s))
		}
	}
	return cfg, nil
}

// RetryResourceOp wraps older CRUD hooks that return error (Create/Update/Delete).
// When a retry block is configured, fn is called with the no-provider-retry meta
// so only resource retry is active.
func RetryResourceOp(d *schema.ResourceData, providerDeps interface{}, fn func(providerDeps interface{}) error) error {
	cfg, err := resourceRetryConfigFromData(d)
	if err != nil {
		return err
	}
	if cfg == nil {
		return fn(providerDeps)
	}
	providerDeps = NoRetryMeta(providerDeps)
	return cfg.run(func() error { return fn(providerDeps) })
}

// RetryResourceOpDiag wraps Context CRUD hooks that return diag.Diagnostics
// (CreateContext/UpdateContext/DeleteContext). Same retry policy as RetryResourceOp.
func RetryResourceOpDiag(d *schema.ResourceData, providerDeps interface{}, fn func(providerDeps interface{}) diag.Diagnostics) diag.Diagnostics {
	cfg, err := resourceRetryConfigFromData(d)
	if err != nil {
		return diag.FromErr(err)
	}
	if cfg == nil {
		return fn(providerDeps)
	}
	providerDeps = NoRetryMeta(providerDeps)

	var last diag.Diagnostics
	_ = cfg.run(func() error {
		last = fn(providerDeps)
		if !last.HasError() {
			return nil
		}
		return fmt.Errorf("%s", diagnosticsMessage(last))
	})
	return last
}

// run is the shared resource-retry loop. Provider HTTP retry is already disabled
// for these calls via the no-retry meta passed to fn.
func (cfg *resourceRetryConfig) run(fn func() error) error {
	attempt := 0
	var lastErr error
	err := retry.RetryContext(context.Background(), sdkRetryTimeout, func() *retry.RetryError {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if attempt >= cfg.MaxRetries || !cfg.matches(lastErr.Error()) {
			return retry.NonRetryableError(lastErr)
		}
		wait := cfg.backoff(attempt)
		log.Printf("[DEBUG] akeyless: resource retry attempt %d/%d after %s: %v", attempt+1, cfg.MaxRetries, wait, lastErr)
		time.Sleep(wait)
		attempt++
		return retry.RetryableError(lastErr)
	})
	if lastErr != nil {
		return lastErr
	}
	return err
}

// diagnosticsMessage returns the first error text so resource retry can match retry_on_messages.
func diagnosticsMessage(diags diag.Diagnostics) string {
	for _, d := range diags {
		if d.Severity != diag.Error {
			continue
		}
		if d.Detail != "" {
			return d.Summary + " " + d.Detail
		}
		return d.Summary
	}
	return ""
}

func (c *resourceRetryConfig) matches(msg string) bool {
	for _, re := range c.ErrorMessageRegex {
		if re.MatchString(msg) {
			return true
		}
	}
	return false
}

// backoff computes how long to wait before the next resource-level retry.
func (c *resourceRetryConfig) backoff(attempt int) time.Duration {
	base := c.IntervalSeconds * math.Pow(c.Multiplier, float64(attempt))
	d := time.Duration(base * float64(time.Second))
	max := time.Duration(c.MaxIntervalSeconds * float64(time.Second))
	if max > 0 && d > max {
		return max
	}
	return d
}
