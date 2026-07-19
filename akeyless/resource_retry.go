package akeyless

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// resource-level retry default backoff values.
const (
	resourceRetryDefaultMaxRetries         = 3
	resourceRetryDefaultIntervalSeconds    = 10.0
	resourceRetryDefaultMaxIntervalSeconds = 180.0
	resourceRetryDefaultMultiplier         = 1.5
)

// resourceRetrySchema is the optional resource-level retry block. When set, the
// resource's API calls retry with these settings instead of the provider defaults.
func resourceRetrySchema() *schema.Schema {
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
					Description: "Additional response-body message texts that trigger a retry (on top of connection errors and rate-limit responses).",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				"interval_seconds": {
					Type:        schema.TypeFloat,
					Optional:    true,
					Default:     resourceRetryDefaultIntervalSeconds,
					Description: "Initial backoff interval in seconds.",
				},
				"max_interval_seconds": {
					Type:        schema.TypeFloat,
					Optional:    true,
					Default:     resourceRetryDefaultMaxIntervalSeconds,
					Description: "Maximum backoff interval in seconds.",
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
					Default:     resourceRetryDefaultMaxRetries,
					Description: "Maximum number of retries after the first attempt.",
				},
			},
		},
	}
}

// EnableResourceRetry adds the retry block to the resource and makes each CRUD hook
// use a resource-configured retry client when the block is set. With no retry block,
// the resource keeps using the provider client unchanged.
func EnableResourceRetry(r *schema.Resource) {
	if r == nil {
		return
	}
	if r.Schema == nil {
		r.Schema = map[string]*schema.Schema{}
	}
	if _, exists := r.Schema["retry"]; !exists {
		s := resourceRetrySchema()
		// Create-only resources (no Update) require ForceNew on every schema attribute.
		if r.Update == nil && r.UpdateContext == nil {
			s.ForceNew = true
		}
		r.Schema["retry"] = s
	}

	if r.Create != nil {
		orig := r.Create
		r.Create = func(d *schema.ResourceData, m interface{}) error {
			deps, err := resourceRetryDeps(d, m)
			if err != nil {
				return err
			}
			return orig(d, deps)
		}
	}
	if r.Update != nil {
		orig := r.Update
		r.Update = func(d *schema.ResourceData, m interface{}) error {
			deps, err := resourceRetryDeps(d, m)
			if err != nil {
				return err
			}
			return orig(d, deps)
		}
	}
	if r.Delete != nil {
		orig := r.Delete
		r.Delete = func(d *schema.ResourceData, m interface{}) error {
			deps, err := resourceRetryDeps(d, m)
			if err != nil {
				return err
			}
			return orig(d, deps)
		}
	}
	if r.CreateContext != nil {
		orig := r.CreateContext
		r.CreateContext = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
			deps, err := resourceRetryDeps(d, m)
			if err != nil {
				return diag.FromErr(err)
			}
			return orig(ctx, d, deps)
		}
	}
	if r.UpdateContext != nil {
		orig := r.UpdateContext
		r.UpdateContext = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
			deps, err := resourceRetryDeps(d, m)
			if err != nil {
				return diag.FromErr(err)
			}
			return orig(ctx, d, deps)
		}
	}
	if r.DeleteContext != nil {
		orig := r.DeleteContext
		r.DeleteContext = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
			deps, err := resourceRetryDeps(d, m)
			if err != nil {
				return diag.FromErr(err)
			}
			return orig(ctx, d, deps)
		}
	}
}

// resourceRetryDeps returns the provider meta to use for this operation. When the
// resource has a retry {} block, it returns a copy whose client retries per the
// block's settings; otherwise it returns m unchanged (provider retry applies).
func resourceRetryDeps(d *schema.ResourceData, m interface{}) (interface{}, error) {
	cfg, ok, err := resourceRetryConfigFromData(d)
	if err != nil {
		return nil, err
	}
	pm, isMeta := m.(*providerMeta)
	if !ok || !isMeta || pm == nil {
		return m, nil
	}

	cp := *pm // shallow copy shares the token
	cp.client = buildAPIClient(pm.apiGwAddress, newRetryTransport(http.DefaultTransport, cfg))
	return &cp, nil
}

// resourceRetryConfigFromData builds a transport retry config from the resource's
// retry {} block. ok is false when the block is absent.
func resourceRetryConfigFromData(d *schema.ResourceData) (cfg retryConfig, ok bool, err error) {
	raw := d.Get("retry").([]interface{})
	if len(raw) == 0 || raw[0] == nil {
		return retryConfig{}, false, nil
	}
	m := raw[0].(map[string]interface{})

	// Start from provider defaults so the resource still retries busy status codes
	// and rate-limit responses; then apply the block's overrides.
	cfg = defaultRetryConfig()
	if v, ok := m["max_retries"].(int); ok {
		cfg.MaxRetries = v
	}
	if v, ok := m["interval_seconds"].(float64); ok {
		cfg.IntervalSeconds = v
	}
	if v, ok := m["max_interval_seconds"].(float64); ok {
		cfg.MaxBackoffSeconds = v
	}
	if v, ok := m["multiplier"].(float64); ok {
		cfg.Multiplier = v
	}

	if patterns, ok := m["retry_on_messages"].([]interface{}); ok {
		regexes := make([]*regexp.Regexp, 0, len(patterns))
		for _, p := range patterns {
			s, ok := p.(string)
			if !ok || s == "" {
				continue
			}
			re, err := regexp.Compile(s)
			if err != nil {
				return retryConfig{}, false, fmt.Errorf("invalid retry.retry_on_messages %q: %w", s, err)
			}
			regexes = append(regexes, re)
		}
		cfg.ErrorMessageRegex = regexes
	}
	return cfg, true, nil
}
