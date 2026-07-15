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
	defaultMaxRetries          = 3
	defaultIntervalSeconds     = 1.0
	defaultMaxBackoffSeconds   = 30.0
	defaultMultiplier          = 1.5
	defaultRandomizationFactor = 0.5
)

// busyHTTPStatusCodes are retried by default. Edit this list to add/remove statuses.
var busyHTTPStatusCodes = []int{429, 500, 502, 503, 504}

// releaseHintRE matches Akeyless SaaS rate-limit bodies: "will be released in 14.148893476s"
var releaseHintRE = regexp.MustCompile(`(?i)will be released in\s+([0-9]+(?:\.[0-9]+)?)\s*s`)

// rateLimitBodyRE detects SaaS rate limiting even when wrapped in another HTTP status (e.g. 403).
var rateLimitBodyRE = regexp.MustCompile(`(?i)(429\s+Too Many Requests|Too Many Requests|will be released in)`)

type retryConfig struct {
	MaxRetries          int
	RetryOnStatusCodes  map[int]struct{}
	IntervalSeconds     float64
	MaxBackoffSeconds   float64
	Multiplier          float64
	RandomizationFactor float64
	ErrorMessageRegex   []*regexp.Regexp
}

func defaultRetryConfig() retryConfig {
	return retryConfig{
		MaxRetries:          defaultMaxRetries,
		RetryOnStatusCodes:  statusCodeSet(busyHTTPStatusCodes),
		IntervalSeconds:     defaultIntervalSeconds,
		MaxBackoffSeconds:   defaultMaxBackoffSeconds,
		Multiplier:          defaultMultiplier,
		RandomizationFactor: defaultRandomizationFactor,
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
					Description: "Initial backoff interval in seconds when Retry-After / release hint is absent. Env: AKEYLESS_RETRY_INTERVAL_SECONDS.",
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
				"randomization_factor": {
					Type:        schema.TypeFloat,
					Optional:    true,
					Default:     defaultRandomizationFactor,
					Description: "Jitter factor applied to backoff intervals. Env: AKEYLESS_RETRY_RANDOMIZATION_FACTOR.",
				},
				"error_message_regex": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "Additional regexes matched against response bodies to trigger a retry.",
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
		if v, ok := m["randomization_factor"].(float64); ok {
			cfg.RandomizationFactor = v
		}
		if codes, ok := m["retry_on_status_codes"].([]interface{}); ok && len(codes) > 0 {
			parsed := make([]int, 0, len(codes))
			for _, c := range codes {
				parsed = append(parsed, c.(int))
			}
			cfg.RetryOnStatusCodes = statusCodeSet(parsed)
		}
		if patterns, ok := m["error_message_regex"].([]interface{}); ok {
			regexes := make([]*regexp.Regexp, 0, len(patterns))
			for _, p := range patterns {
				s, ok := p.(string)
				if !ok || s == "" {
					continue
				}
				re, err := regexp.Compile(s)
				if err != nil {
					return cfg, fmt.Errorf("invalid error_message_regex %q: %w", s, err)
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
	if v := os.Getenv("AKEYLESS_RETRY_RANDOMIZATION_FACTOR"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.RandomizationFactor = f
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

func parseReleaseHintSeconds(body string) (float64, bool) {
	m := releaseHintRE.FindStringSubmatch(body)
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
