package akeyless

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	busyRetryInitialWait = 1 * time.Second
	busyRetryMaxWait     = 30 * time.Second
)

var busyStatusCodes = map[int]bool{
	http.StatusTooManyRequests:     true,
	http.StatusInternalServerError: true,
	http.StatusBadGateway:          true,
	http.StatusServiceUnavailable:  true,
	http.StatusGatewayTimeout:      true,
}

// rateLimitBodyRE matches SaaS rate-limit errors, which may be wrapped in another status (e.g. 403).
var rateLimitBodyRE = regexp.MustCompile(`(?i)too many requests|will be released in`)

// releaseDelayRE extracts the wait from "will be released in 14.15s".
var releaseDelayRE = regexp.MustCompile(`(?i)will be released in\s+([0-9]+(?:\.[0-9]+)?)\s*s`)

// busyRetryTransport retries busy API responses. It is used only when
// maximum_busy_retry_attempts > 0.
type busyRetryTransport struct {
	base     http.RoundTripper
	attempts int
	sleep    func(ctx context.Context, d time.Duration) error
}

func newBusyRetryTransport(base http.RoundTripper, attempts int) *busyRetryTransport {
	return &busyRetryTransport{base: base, attempts: attempts, sleep: sleepContext}
}

func (t *busyRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
	}

	for retry := 0; ; retry++ {
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		resp, err := t.base.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))

		if retry >= t.attempts || !isBusyResponse(resp.StatusCode, string(body)) {
			return resp, nil
		}

		wait := busyRetryWait(retry, resp.Header.Get("Retry-After"), string(body))
		log.Printf("[INFO] akeyless: busy response HTTP %d, retry %d/%d after %s path=%s",
			resp.StatusCode, retry+1, t.attempts, wait, req.URL.Path)
		if err := t.sleep(req.Context(), wait); err != nil {
			return nil, err
		}
	}
}

func isBusyResponse(status int, body string) bool {
	return busyStatusCodes[status] || rateLimitBodyRE.MatchString(body)
}

// busyRetryWait uses Retry-After, then "will be released in Ns", then exponential backoff.
func busyRetryWait(retry int, retryAfter, body string) time.Duration {
	if sec, err := strconv.ParseFloat(strings.TrimSpace(retryAfter), 64); err == nil {
		return capWait(time.Duration(sec*float64(time.Second)), busyRetryMaxWait)
	}
	if when, err := http.ParseTime(retryAfter); err == nil {
		return capWait(time.Until(when), busyRetryMaxWait)
	}
	if m := releaseDelayRE.FindStringSubmatch(body); len(m) == 2 {
		if sec, err := strconv.ParseFloat(m[1], 64); err == nil {
			return capWait(time.Duration(sec*float64(time.Second)), busyRetryMaxWait)
		}
	}
	return backoffWait(busyRetryInitialWait, busyRetryMaxWait, retry)
}

// backoffWait returns initial * 2^retry, capped at max.
func backoffWait(initial, max time.Duration, retry int) time.Duration {
	wait := initial
	for i := 0; i < retry && wait < max; i++ {
		wait *= 2
	}
	return capWait(wait, max)
}

func capWait(d, max time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	if d > max {
		return max
	}
	return d
}

// sleepContext waits for d, or returns early when ctx is cancelled.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
