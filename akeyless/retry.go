package akeyless

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
)

// Shared retry defaults (provider and resource may override).
const (
	defaultMaxRetries        = 3
	defaultIntervalSeconds   = 2.0
	defaultMaxBackoffSeconds = 60.0
	defaultMultiplier        = 2.0
)

// sdkRetryTimeout is intentionally large: we stop via max_retries, not timeout.
const sdkRetryTimeout = 24 * time.Hour

// busyHTTPStatusCodes are retried by default.
var busyHTTPStatusCodes = []int{429, 500, 502, 503, 504}

// releaseDelayRE extracts wait seconds from "will be released in 14.15s".
var releaseDelayRE = regexp.MustCompile(`(?i)will be released in\s+([0-9]+(?:\.[0-9]+)?)\s*s`)

// rateLimitBodyRE detects rate limiting in response body.
var rateLimitBodyRE = regexp.MustCompile(`(?i)(429\s+Too Many Requests|Too Many Requests|will be released in)`)

// retryConfig holds retry settings for the HTTP transport.
type retryConfig struct {
	MaxRetries         int
	RetryOnStatusCodes map[int]struct{}
	IntervalSeconds    float64
	MaxBackoffSeconds  float64
	Multiplier         float64
	ErrorMessageRegex  []*regexp.Regexp
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

// retryTransport wraps http.RoundTripper with retry logic.
type retryTransport struct {
	base  http.RoundTripper
	cfg   retryConfig
	sleep func(ctx context.Context, d time.Duration) error
}

func newRetryTransport(base http.RoundTripper, cfg retryConfig) *retryTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &retryTransport{
		base: base,
		cfg:  cfg,
		sleep: func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
	}

	maxAttempts := t.cfg.MaxRetries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	attempt := 0
	var finalResp *http.Response
	var finalErr error

	err := retry.RetryContext(req.Context(), sdkRetryTimeout, func() *retry.RetryError {
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		resp, err := t.base.RoundTrip(req)
		if err != nil {
			return t.onConnError(req.Context(), err, &attempt, maxAttempts, &finalErr)
		}
		return t.onHTTPResponse(req, resp, &attempt, maxAttempts, &finalResp, &finalErr)
	})

	if finalResp != nil {
		return finalResp, nil
	}
	if finalErr != nil {
		return nil, finalErr
	}
	return nil, err
}

func (t *retryTransport) onConnError(ctx context.Context, err error, attempt *int, maxAttempts int, finalErr *error) *retry.RetryError {
	if !isTransientConnError(err) || *attempt >= maxAttempts-1 {
		*finalErr = err
		return retry.NonRetryableError(err)
	}
	wait := time.Duration((*attempt+1)*2) * time.Second
	log.Printf("[INFO] akeyless: retrying connection error (attempt %d/%d) after %s: %v", *attempt+1, maxAttempts, wait, err)
	if sleepErr := t.sleep(ctx, wait); sleepErr != nil {
		*finalErr = sleepErr
		return retry.NonRetryableError(sleepErr)
	}
	*attempt++
	return retry.RetryableError(err)
}

func (t *retryTransport) onHTTPResponse(req *http.Request, resp *http.Response, attempt *int, maxAttempts int, finalResp **http.Response, finalErr *error) *retry.RetryError {
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		*finalErr = readErr
		return retry.NonRetryableError(readErr)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))

	if !t.shouldRetry(resp.StatusCode, string(body)) || *attempt >= maxAttempts-1 {
		*finalResp = resp
		return nil
	}

	wait := t.waitDuration(*attempt, resp, string(body))
	log.Printf("[INFO] akeyless: retrying HTTP %d (attempt %d/%d) after %s path=%s",
		resp.StatusCode, *attempt+1, maxAttempts, wait, req.URL.Path)
	if sleepErr := t.sleep(req.Context(), wait); sleepErr != nil {
		*finalErr = sleepErr
		return retry.NonRetryableError(sleepErr)
	}
	*attempt++
	return retry.RetryableError(fmt.Errorf("HTTP %d", resp.StatusCode))
}

func (t *retryTransport) shouldRetry(status int, body string) bool {
	if _, ok := t.cfg.RetryOnStatusCodes[status]; ok {
		return true
	}
	if bodyLooksLikeRateLimit(body) {
		return true
	}
	for _, re := range t.cfg.ErrorMessageRegex {
		if re.MatchString(body) {
			return true
		}
	}
	return false
}

func (t *retryTransport) waitDuration(attempt int, resp *http.Response, body string) time.Duration {
	if resp != nil {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if sec, err := strconv.ParseFloat(strings.TrimSpace(ra), 64); err == nil {
				return t.capDuration(time.Duration(sec * float64(time.Second)))
			}
			if when, err := http.ParseTime(ra); err == nil {
				d := time.Until(when)
				if d < 0 {
					d = 0
				}
				return t.capDuration(d)
			}
		}
	}
	if sec, ok := parseReleaseDelaySeconds(body); ok {
		return t.capDuration(time.Duration(sec * float64(time.Second)))
	}
	return t.backoffDuration(attempt)
}

func (t *retryTransport) backoffDuration(attempt int) time.Duration {
	base := t.cfg.IntervalSeconds * math.Pow(t.cfg.Multiplier, float64(attempt))
	return t.capDuration(time.Duration(base * float64(time.Second)))
}

func (t *retryTransport) capDuration(d time.Duration) time.Duration {
	max := time.Duration(t.cfg.MaxBackoffSeconds * float64(time.Second))
	if max > 0 && d > max {
		return max
	}
	if d < 0 {
		return 0
	}
	return d
}

// --- Helpers ---

func statusCodeSet(codes []int) map[int]struct{} {
	out := make(map[int]struct{}, len(codes))
	for _, c := range codes {
		out[c] = struct{}{}
	}
	return out
}

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
