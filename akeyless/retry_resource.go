package akeyless

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// resourceRetrySchema returns the optional resource-level retry {} block schema.
// When set, overrides provider HTTP retry for this resource.
func resourceRetrySchema() *schema.Schema {
	return &schema.Schema{
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Optional resource-level retry. When set, overrides provider HTTP retry.",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"max_retries": {
					Type:        schema.TypeInt,
					Optional:    true,
					Default:     defaultMaxRetries,
					Description: "Maximum retries after the first attempt.",
				},
				"retry_on_status_codes": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "HTTP status codes that trigger a retry. Defaults to 429, 500, 502, 503, 504.",
					Elem:        &schema.Schema{Type: schema.TypeInt},
				},
				"interval_seconds": {
					Type:        schema.TypeFloat,
					Optional:    true,
					Default:     defaultIntervalSeconds,
					Description: "Initial backoff interval in seconds.",
				},
				"max_backoff_seconds": {
					Type:        schema.TypeFloat,
					Optional:    true,
					Default:     defaultMaxBackoffSeconds,
					Description: "Maximum backoff interval in seconds.",
				},
				"multiplier": {
					Type:        schema.TypeFloat,
					Optional:    true,
					Default:     defaultMultiplier,
					Description: "Exponential backoff multiplier.",
				},
				"retry_on_messages": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "Extra error messages that trigger a retry (matched as regex).",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
			},
		},
	}
}

// EnableResourceRetry adds the retry {} block to a resource and wraps CRUD hooks.
// When a resource has a retry block, its operations use a custom-configured client.
func EnableResourceRetry(r *schema.Resource) {
	if r == nil {
		return
	}
	if r.Schema == nil {
		r.Schema = map[string]*schema.Schema{}
	}
	if _, exists := r.Schema["retry"]; !exists {
		s := resourceRetrySchema()
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

// resourceRetryDeps returns provider meta with a custom retry client when
// a retry {} block is present; otherwise returns the original meta unchanged.
func resourceRetryDeps(d *schema.ResourceData, m interface{}) (interface{}, error) {
	cfg, ok, err := resourceRetryConfigFromData(d)
	if err != nil {
		return nil, err
	}
	pm, isMeta := m.(*providerMeta)
	if !ok || !isMeta || pm == nil {
		return m, nil // no retry block set → use provider client
	}
	// resource retry {} set → new client with resource cfg
	cp := *pm
	cp.client = buildAPIClient(pm.apiGwAddress, newRetryTransport(http.DefaultTransport, cfg))
	return &cp, nil
}

// resourceRetryConfigFromData parses the resource's retry {} block.
// Returns ok=false when block is absent.
func resourceRetryConfigFromData(d *schema.ResourceData) (cfg retryConfig, ok bool, err error) {
	raw := d.Get("retry").([]interface{})
	if len(raw) == 0 || raw[0] == nil {
		return retryConfig{}, false, nil
	}

	m := raw[0].(map[string]interface{})
	cfg = defaultRetryConfig()

	if v, ok := m["max_retries"].(int); ok {
		cfg.MaxRetries = v
	}
	if v, ok := m["interval_seconds"].(float64); ok {
		cfg.IntervalSeconds = v
	}
	if v, ok := m["max_backoff_seconds"].(float64); ok {
		cfg.MaxBackoffSeconds = v
	}
	if v, ok := m["multiplier"].(float64); ok {
		cfg.Multiplier = v
	}
	if codes, ok := m["retry_on_status_codes"].([]interface{}); ok && len(codes) > 0 {
		parsed := make([]int, 0, len(codes))
		for _, c := range codes {
			parsed = append(parsed, c.(int))
		}
		cfg.RetryOnStatusCodes = statusCodeSet(parsed)
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
