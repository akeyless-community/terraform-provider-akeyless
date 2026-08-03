package common

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"
)

// NewRetryHTTPClient returns an *http.Client that retries requests a fixed
// number of times on transient connection errors. Shared by the SDK v2
// provider and the Framework provider so both auth codepaths behave
// identically.
func NewRetryHTTPClient(retries int) *http.Client {
	return &http.Client{
		Transport: &retryTransport{base: http.DefaultTransport, retries: retries},
	}
}

type retryTransport struct {
	base    http.RoundTripper
	retries int
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

	var lastErr error
	for attempt := range t.retries {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		resp, err := t.base.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !isTransientConnError(err) {
			return nil, err
		}
	}
	return nil, lastErr
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
