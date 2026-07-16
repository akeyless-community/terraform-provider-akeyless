package akeyless

import (
	"bytes"
	"context"
	"io"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// retryTransport is the provider-level HTTP retry (all API calls).
// Resource-level retry lives in akeyless/common/retry.go and runs later, on CRUD errors.
type retryTransport struct {
	base http.RoundTripper
	cfg  retryConfig
	// sleep is overridable in tests.
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
			timer := time.NewTimer(d) // fire after d
			defer timer.Stop()
			select { // wait for WHICHEVER happens first
			case <-ctx.Done(): // cancel → stop waiting, return error
				return ctx.Err()
			case <-timer.C: // timer finished → OK to retry
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

	// max_retries is attempts beyond the first call.
	retries := t.cfg.MaxRetries + 1
	if retries < 1 {
		retries = 1
	}

	var lastErr error
	for attempt := range retries {
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		resp, err := t.base.RoundTrip(req)
		if err != nil {
			lastErr = err
			if !isTransientConnError(err) {
				return nil, err
			}
			if attempt == retries-1 {
				return nil, lastErr
			}
			wait := time.Duration((attempt+1)*2) * time.Second
			log.Printf("[INFO] akeyless: retrying connection error (attempt %d/%d) after %s: %v", attempt+1, retries, wait, err)
			if sleepErr := t.sleep(req.Context(), wait); sleepErr != nil {
				return nil, sleepErr
			}
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))

		if !t.shouldRetry(resp.StatusCode, string(body)) || attempt == retries-1 {
			return resp, nil
		}

		wait := t.waitDuration(attempt, resp, string(body))
		log.Printf("[INFO] akeyless: retrying HTTP %d (attempt %d/%d) after %s path=%s",
			resp.StatusCode, attempt+1, retries, wait, req.URL.Path)
		if sleepErr := t.sleep(req.Context(), wait); sleepErr != nil {
			return nil, sleepErr
		}
	}
	return nil, lastErr
}

// shouldRetry: true if status is busy, or body looks like rate-limit, or a customer regex matches.
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
			// second try against response body (HTTP-date)
			if when, err := http.ParseTime(ra); err == nil {
				d := time.Until(when)
				if d < 0 {
					d = 0
				}
				return t.capDuration(d)
			}
		}
	}
	// Same idea as Retry-After, but delay taken from the response body.
	if sec, ok := parseReleaseDelaySeconds(body); ok {
		return t.capDuration(time.Duration(sec * float64(time.Second)))
	}
	return t.backoffDuration(attempt)
}

func (t *retryTransport) backoffDuration(attempt int) time.Duration {
	base := t.cfg.IntervalSeconds * math.Pow(t.cfg.Multiplier, float64(attempt))
	return t.capDuration(time.Duration(base * float64(time.Second)))
}

// capDuration limits wait to MaxBackoffSeconds so Retry-After / body delay cannot stall forever.
func (t *retryTransport) capDuration(d time.Duration) time.Duration {
	max := time.Duration(t.cfg.MaxBackoffSeconds * float64(time.Second))
	if max > 0 && d > max {
		return max // asked wait is longer than the configured cap
	}
	if d < 0 {
		return 0
	}
	return d
}
