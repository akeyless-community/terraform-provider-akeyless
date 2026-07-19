package common

import (
	"bytes"
	"runtime"
	"strconv"
	"sync"
)

// skipProviderHTTPRetry is a per-worker "resource retry is active" flag.
// Keyed by goroutine id so parallel Terraform resource workers stay isolated:
// if resource A has retry {}, only A's HTTP calls skip provider retry; resource B
// (no resource retry) still uses provider HTTP retry. A single global bool would
// incorrectly disable provider retry for every concurrent worker.
var skipProviderHTTPRetry sync.Map // goroutineID -> struct{}

// SetSkipProviderHTTPRetry marks (or clears) "skip provider HTTP retry" for the
// current worker only. Used while a resource-level retry {} attempt is in flight.
func SetSkipProviderHTTPRetry(skip bool) {
	id := goroutineID()
	if skip {
		skipProviderHTTPRetry.Store(id, struct{}{})
		return
	}
	skipProviderHTTPRetry.Delete(id)
}

// SkipProviderHTTPRetry is true when the current worker has resource retry active
// (see SetSkipProviderHTTPRetry). Checked from the HTTP transport.
func SkipProviderHTTPRetry() bool {
	_, ok := skipProviderHTTPRetry.Load(goroutineID())
	return ok
}

func goroutineID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	// "goroutine 123 [running]:..."
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	i := bytes.IndexByte(b, ' ')
	if i <= 0 {
		return 0
	}
	id, _ := strconv.ParseUint(string(b[:i]), 10, 64)
	return id
}
