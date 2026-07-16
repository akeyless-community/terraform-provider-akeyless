package common

import (
	"context"
	"fmt"
	"log"
	"math"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	resourceRetryDefaultIntervalSeconds    = 10.0
	resourceRetryDefaultMaxIntervalSeconds = 180.0
	resourceRetryDefaultMultiplier         = 1.5
)

// ResourceRetrySchema is the optional resource-level retry block (after provider HTTP retry).
func ResourceRetrySchema() *schema.Schema {
	return &schema.Schema{
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Optional resource-level retry. Runs after provider HTTP retries; matches error messages.",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"error_message_regex": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "Regexes matched against error messages. If any match, the operation is retried.",
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
		r.Create = func(d *schema.ResourceData, m interface{}) error {
			return RetryResourceOp(d, func() error { return orig(d, m) })
		}
	}
	if r.Update != nil {
		orig := r.Update
		r.Update = func(d *schema.ResourceData, m interface{}) error {
			return RetryResourceOp(d, func() error { return orig(d, m) })
		}
	}
	if r.Delete != nil {
		orig := r.Delete
		r.Delete = func(d *schema.ResourceData, m interface{}) error {
			return RetryResourceOp(d, func() error { return orig(d, m) })
		}
	}
	if r.CreateContext != nil {
		orig := r.CreateContext
		r.CreateContext = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
			return RetryResourceOpDiag(d, func() diag.Diagnostics { return orig(ctx, d, m) })
		}
	}
	if r.UpdateContext != nil {
		orig := r.UpdateContext
		r.UpdateContext = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
			return RetryResourceOpDiag(d, func() diag.Diagnostics { return orig(ctx, d, m) })
		}
	}
	if r.DeleteContext != nil {
		orig := r.DeleteContext
		r.DeleteContext = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
			return RetryResourceOpDiag(d, func() diag.Diagnostics { return orig(ctx, d, m) })
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

	patterns, _ := m["error_message_regex"].([]interface{})
	for _, p := range patterns {
		s, ok := p.(string)
		if !ok || s == "" {
			continue
		}
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("invalid retry.error_message_regex %q: %w", s, err)
		}
		cfg.ErrorMessageRegex = append(cfg.ErrorMessageRegex, re)
	}
	if len(cfg.ErrorMessageRegex) == 0 {
		// Without message matchers, resource-level retry would retry every error — refuse that.
		return nil, fmt.Errorf("retry.error_message_regex must contain at least one pattern")
	}
	return cfg, nil
}

// RetryResourceOp runs fn, retrying when a resource retry block matches the error message.
func RetryResourceOp(d *schema.ResourceData, fn func() error) error {
	cfg, err := resourceRetryConfigFromData(d)
	if err != nil {
		return err
	}
	if cfg == nil {
		return fn()
	}

	var lastErr error
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if attempt == cfg.MaxRetries || !cfg.matches(lastErr.Error()) {
			return lastErr
		}
		wait := cfg.backoff(attempt)
		log.Printf("[DEBUG] akeyless: resource retry attempt %d/%d after %s: %v", attempt+1, cfg.MaxRetries, wait, lastErr)
		time.Sleep(wait)
	}
	return lastErr
}

// RetryResourceOpDiag is the Context-CRUD equivalent of RetryResourceOp.
func RetryResourceOpDiag(d *schema.ResourceData, fn func() diag.Diagnostics) diag.Diagnostics {
	cfg, err := resourceRetryConfigFromData(d)
	if err != nil {
		return diag.FromErr(err)
	}
	if cfg == nil {
		return fn()
	}

	var last diag.Diagnostics
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		last = fn()
		if !last.HasError() {
			return last
		}
		msg := diagnosticsMessage(last)
		if attempt == cfg.MaxRetries || !cfg.matches(msg) {
			return last
		}
		wait := cfg.backoff(attempt)
		log.Printf("[DEBUG] akeyless: resource retry attempt %d/%d after %s: %s", attempt+1, cfg.MaxRetries, wait, msg)
		time.Sleep(wait)
	}
	return last
}

// diagnosticsMessage returns the first error text so resource retry can match error_message_regex.
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
