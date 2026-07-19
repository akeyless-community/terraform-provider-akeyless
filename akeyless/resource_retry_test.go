package akeyless

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceWithRetrySchema() *schema.Resource {
	r := &schema.Resource{Schema: map[string]*schema.Schema{}}
	r.Schema["retry"] = resourceRetrySchema()
	return r
}

func TestResourceRetryConfig_Absent(t *testing.T) {
	r := resourceWithRetrySchema()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{})

	_, ok, err := resourceRetryConfigFromData(d)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false when no retry block is set")
	}
}

func TestResourceRetryConfig_OverridesAndDefaults(t *testing.T) {
	r := resourceWithRetrySchema()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{
			map[string]interface{}{
				"max_retries":          5,
				"interval_seconds":     2.0,
				"max_interval_seconds": 20.0,
				"multiplier":           3.0,
				"retry_on_messages":    []interface{}{"custom error"},
			},
		},
	})

	cfg, ok, err := resourceRetryConfigFromData(d)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true when retry block is set")
	}
	if cfg.MaxRetries != 5 || cfg.IntervalSeconds != 2.0 || cfg.MaxBackoffSeconds != 20.0 || cfg.Multiplier != 3.0 {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}
	// Default busy status codes are inherited from the provider defaults.
	if _, retried := cfg.RetryOnStatusCodes[429]; !retried {
		t.Fatal("expected default busy status codes to be inherited")
	}
	if len(cfg.ErrorMessageRegex) != 1 || !cfg.ErrorMessageRegex[0].MatchString("a custom error b") {
		t.Fatalf("retry_on_messages not compiled: %+v", cfg.ErrorMessageRegex)
	}
}

func TestResourceRetryConfig_InvalidRegexErrors(t *testing.T) {
	r := resourceWithRetrySchema()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{
			map[string]interface{}{
				"retry_on_messages": []interface{}{"("},
			},
		},
	})

	if _, _, err := resourceRetryConfigFromData(d); err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestResourceRetryDeps_SwapsClientOnlyWhenConfigured(t *testing.T) {
	r := resourceWithRetrySchema()
	pm := &providerMeta{apiGwAddress: "https://api.example.com"}

	// No retry block -> same meta is returned.
	noRetry := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{})
	got, err := resourceRetryDeps(noRetry, pm)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != interface{}(pm) {
		t.Fatal("expected unchanged meta when no retry block")
	}

	// With retry block -> a copy with a freshly built client is returned.
	withRetry := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"retry": []interface{}{map[string]interface{}{"max_retries": 1}},
	})
	got, err = resourceRetryDeps(withRetry, pm)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	cp, ok := got.(*providerMeta)
	if !ok || cp == pm {
		t.Fatal("expected a distinct providerMeta copy")
	}
	if cp.client == nil {
		t.Fatal("expected a resource retry client to be built")
	}
}
