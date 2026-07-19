package common

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestRetryResourceOp_NoConfig(t *testing.T) {
	r := &schema.Resource{Schema: map[string]*schema.Schema{}}
	AddResourceRetrySchema(r.Schema)
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{})

	calls := 0
	err := RetryResourceOp(d, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d want 1", calls)
	}
}

func TestRetryResourceOp_MatchesAndRetries(t *testing.T) {
	r := &schema.Resource{Schema: map[string]*schema.Schema{}}
	AddResourceRetrySchema(r.Schema)
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{
			map[string]interface{}{
				"retry_on_messages":  []interface{}{"Too Many Requests"},
				"interval_seconds":     0.01,
				"max_interval_seconds": 0.05,
				"max_retries":          2,
				"multiplier":           1.0,
			},
		},
	})

	var calls int32
	err := RetryResourceOp(d, func() error {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			return errors.New("429 Too Many Requests")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls=%d want 3", calls)
	}
}

func TestRetryResourceOp_NoMatch(t *testing.T) {
	r := &schema.Resource{Schema: map[string]*schema.Schema{}}
	AddResourceRetrySchema(r.Schema)
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{
			map[string]interface{}{
				"retry_on_messages": []interface{}{"will be released in"},
				"interval_seconds":    0.01,
				"max_retries":         3,
			},
		},
	})

	calls := 0
	err := RetryResourceOp(d, func() error {
		calls++
		return errors.New("permission denied")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("calls=%d want 1", calls)
	}
}

func TestRetryResourceOp_DefaultRegexWhenOmitted(t *testing.T) {
	r := &schema.Resource{Schema: map[string]*schema.Schema{}}
	AddResourceRetrySchema(r.Schema)
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{
			map[string]interface{}{
				"interval_seconds": 0.01,
				"max_retries":      2,
				"multiplier":       1.0,
			},
		},
	})

	var calls int32
	err := RetryResourceOp(d, func() error {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			return errors.New("429 Too Many Requests")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls=%d want 3", calls)
	}
}

func TestRetryResourceOp_SkipsProviderHTTPRetry(t *testing.T) {
	r := &schema.Resource{Schema: map[string]*schema.Schema{}}
	AddResourceRetrySchema(r.Schema)
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{
			map[string]interface{}{
				"retry_on_messages": []interface{}{"x"},
				"max_retries":         0,
			},
		},
	})

	if SkipProviderHTTPRetry() {
		t.Fatal("skip should be off before RetryResourceOp")
	}
	err := RetryResourceOp(d, func() error {
		if !SkipProviderHTTPRetry() {
			t.Fatal("skip should be on during resource retry")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if SkipProviderHTTPRetry() {
		t.Fatal("skip should be off after RetryResourceOp")
	}
}
