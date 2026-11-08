package akeyless

import (
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// providerRetrySchema returns the optional provider-level retry {} block schema.
func providerRetrySchema() *schema.Schema {
	return &schema.Schema{
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Optional HTTP retry configuration. Defaults apply when omitted.",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"max_retries": {
					Type:        schema.TypeInt,
					Optional:    true,
					Default:     defaultMaxRetries,
					Description: "Maximum retries after the first attempt. Env: AKEYLESS_MAX_RETRIES.",
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
					Description: "Initial backoff interval in seconds. Env: AKEYLESS_RETRY_INTERVAL_SECONDS.",
				},
				"max_backoff_seconds": {
					Type:        schema.TypeFloat,
					Optional:    true,
					Default:     defaultMaxBackoffSeconds,
					Description: "Maximum backoff interval in seconds. Env: AKEYLESS_MAX_BACKOFF_SECONDS.",
				},
				"multiplier": {
					Type:        schema.TypeFloat,
					Optional:    true,
					Default:     defaultMultiplier,
					Description: "Exponential backoff multiplier. Env: AKEYLESS_RETRY_MULTIPLIER.",
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

// providerRetryConfigFromData parses the provider's retry {} block into a retryConfig.
func providerRetryConfigFromData(d *schema.ResourceData) (retryConfig, error) {
	cfg := defaultRetryConfig()

	raw := d.Get("retry").([]interface{})
	if len(raw) == 0 || raw[0] == nil {
		return applyRetryEnvOverrides(cfg), nil
	}

	m := raw[0].(map[string]interface{})
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
				return cfg, fmt.Errorf("invalid retry_on_messages %q: %w", s, err)
			}
			regexes = append(regexes, re)
		}
		cfg.ErrorMessageRegex = regexes
	}

	return applyRetryEnvOverrides(cfg), nil
}

func applyRetryEnvOverrides(cfg retryConfig) retryConfig {
	if v := os.Getenv("AKEYLESS_MAX_RETRIES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MaxRetries = n
		}
	}
	if v := os.Getenv("AKEYLESS_RETRY_INTERVAL_SECONDS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.IntervalSeconds = f
		}
	}
	if v := os.Getenv("AKEYLESS_MAX_BACKOFF_SECONDS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.MaxBackoffSeconds = f
		}
	}
	if v := os.Getenv("AKEYLESS_RETRY_MULTIPLIER"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Multiplier = f
		}
	}
	return cfg
}
