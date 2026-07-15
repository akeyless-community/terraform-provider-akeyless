package akeyless

import (
	"bytes"
	"context"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// retryTransport is the single HTTP retry layer for all API calls.
// Connection-error retry keeps the production shape (EOF / reset / refused, attempt*2 sleep).
// Busy HTTP statuses / Retry-After / release hints are added on top.
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

	// Production used a fixed retries count (3 total). PRD max_retries is "beyond first", so +1.
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
			// Production connection backoff: attempt*2 seconds (on the next try).
			wait := time.Duration((attempt+1)*2) * time.Second
			log.Printf("[INFO] akeyless: retrying connection error (attempt %d/%d) after %s: %v", attempt+1, retries, wait, err)
			if sleepErr := t.sleep(req.Context(), wait); sleepErr != nil {
				return nil, sleepErr
			}
			continue
		}

		// Addition: retry busy HTTP statuses / rate-limit bodies (production returned any response as-is).
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
	if sec, ok := parseReleaseHintSeconds(body); ok {
		return t.capDuration(time.Duration(sec * float64(time.Second)))
	}
	return t.backoffDuration(attempt)
}

func (t *retryTransport) backoffDuration(attempt int) time.Duration {
	base := t.cfg.IntervalSeconds * math.Pow(t.cfg.Multiplier, float64(attempt))
	if t.cfg.RandomizationFactor > 0 {
		delta := t.cfg.RandomizationFactor * base
		min := base - delta
		max := base + delta
		if min < 0 {
			min = 0
		}
		base = min + rand.Float64()*(max-min)
	}
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
