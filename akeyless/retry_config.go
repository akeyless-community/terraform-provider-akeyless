package akeyless

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	defaultMaxRetries        = 3
	defaultIntervalSeconds   = 1.0
	defaultMaxBackoffSeconds = 30.0
	defaultMultiplier        = 1.5
)

// busyHTTPStatusCodes are retried by default.
var busyHTTPStatusCodes = []int{429, 500, 502, 503, 504}

// releaseDelayRE extracts wait seconds from SaaS bodies like "will be released in 14.15s".
var releaseDelayRE = regexp.MustCompile(`(?i)will be released in\s+([0-9]+(?:\.[0-9]+)?)\s*s`)

// rateLimitBodyRE detects SaaS rate limiting in the body (also when outer status is e.g. 403).
var rateLimitBodyRE = regexp.MustCompile(`(?i)(429\s+Too Many Requests|Too Many Requests|will be released in)`)

type retryConfig struct {
	MaxRetries         int
	RetryOnStatusCodes map[int]struct{}
	// IntervalSeconds: first wait between retries (default 1s). Used only when no Retry-After/body delay.
	IntervalSeconds float64
	// MaxBackoffSeconds: never wait longer than this (default 30s). Caps IntervalSeconds growth too.
	MaxBackoffSeconds float64
	// Multiplier: each next wait is previous × this (default 1.5).
	Multiplier        float64
	ErrorMessageRegex []*regexp.Regexp
}

func defaultRetryConfig() retryConfig {
	return retryConfig{
		MaxRetries:         defaultMaxRetries,
		RetryOnStatusCodes: statusCodeSet(busyHTTPStatusCodes),
		IntervalSeconds:    defaultIntervalSeconds,
		MaxBackoffSeconds:  defaultMaxBackoffSeconds,
		Multiplier:         defaultMultiplier,
	}
}

func providerRetrySchema() *schema.Schema {
	return &schema.Schema{
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: "Optional HTTP retry configuration. Defaults apply when omitted (connection errors + 429/5xx). See docs/guides/customized_retry.md.",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"max_retries": {
					Type:        schema.TypeInt,
					Optional:    true,
					Default:     defaultMaxRetries,
					Description: "Maximum number of retries after the first attempt. Env: AKEYLESS_MAX_RETRIES.",
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
					Description: "Initial backoff interval in seconds when Retry-After / body release delay is absent. Env: AKEYLESS_RETRY_INTERVAL_SECONDS.",
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
					Description: "Additional response-body message texts that trigger a retry.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
			},
		},
	}
}

func retryConfigFromProviderData(d *schema.ResourceData) (retryConfig, error) {
	cfg := defaultRetryConfig()

	raw := d.Get("retry").([]interface{})
	if len(raw) > 0 && raw[0] != nil {
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

func statusCodeSet(codes []int) map[int]struct{} {
	out := make(map[int]struct{}, len(codes))
	for _, c := range codes {
		out[c] = struct{}{}
	}
	return out
}

// parseReleaseDelaySeconds returns the wait (seconds) from "will be released in Ns" in the body.
func parseReleaseDelaySeconds(body string) (float64, bool) {
	m := releaseDelayRE.FindStringSubmatch(body)
	if len(m) < 2 {
		return 0, false
	}
	sec, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	return sec, true
}

func bodyLooksLikeRateLimit(body string) bool {
	return rateLimitBodyRE.MatchString(body)
}

func isTransientConnError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "connection refused")
}
