package akeyless

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

const (
	defaultRetryIntervalSeconds    = 10
	defaultRetryMaxIntervalSeconds = 180
	defaultRetryMaxRetries         = 3
)

// retrySleep is replaced in tests.
var retrySleep = sleepContext

// retrySchema returns the optional retry {} block. The provider and every resource use the same block.
func retrySchema(description string) *schema.Schema {
	return &schema.Schema{
		Type:        schema.TypeList,
		Optional:    true,
		MaxItems:    1,
		Description: description,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"error_message_regex": {
					Type:        schema.TypeList,
					Required:    true,
					MinItems:    1,
					Description: "Regular expressions matched against the error message. If any matches, the operation is retried.",
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: validation.StringIsValidRegExp,
					},
				},
				"interval_seconds": {
					Type:         schema.TypeInt,
					Optional:     true,
					Default:      defaultRetryIntervalSeconds,
					ValidateFunc: validation.IntAtLeast(1),
					Description:  "Wait before the first retry, in seconds. The wait doubles on each retry.",
				},
				"max_interval_seconds": {
					Type:         schema.TypeInt,
					Optional:     true,
					Default:      defaultRetryMaxIntervalSeconds,
					ValidateFunc: validation.IntAtLeast(1),
					Description:  "Maximum wait between retries, in seconds.",
				},
				"max_retries": {
					Type:         schema.TypeInt,
					Optional:     true,
					Default:      defaultRetryMaxRetries,
					ValidateFunc: validation.IntAtLeast(0),
					Description:  "Maximum number of retries after the first attempt.",
				},
			},
		},
	}
}

type retryConfig struct {
	regexes     []*regexp.Regexp
	interval    time.Duration
	maxInterval time.Duration
	maxRetries  int
}

// retryConfigFromData returns nil when d has no retry {} block.
func retryConfigFromData(d *schema.ResourceData) (*retryConfig, error) {
	raw, ok := d.Get("retry").([]interface{})
	if !ok || len(raw) == 0 || raw[0] == nil {
		return nil, nil
	}
	m := raw[0].(map[string]interface{})

	cfg := &retryConfig{
		interval:    time.Duration(m["interval_seconds"].(int)) * time.Second,
		maxInterval: time.Duration(m["max_interval_seconds"].(int)) * time.Second,
		maxRetries:  m["max_retries"].(int),
	}
	for _, p := range m["error_message_regex"].([]interface{}) {
		re, err := regexp.Compile(p.(string))
		if err != nil {
			return nil, fmt.Errorf("invalid retry.error_message_regex %q: %w", p, err)
		}
		cfg.regexes = append(cfg.regexes, re)
	}
	return cfg, nil
}

func (c *retryConfig) matches(err error) bool {
	if err == nil {
		return false
	}
	for _, re := range c.regexes {
		if re.MatchString(err.Error()) {
			return true
		}
	}
	return false
}

// activeRetryConfig returns the resource retry {} block, or the provider retry {} block
// when the resource has none. It returns nil when neither is set.
func activeRetryConfig(d *schema.ResourceData, m interface{}) (*retryConfig, error) {
	cfg, err := retryConfigFromData(d)
	if err != nil || cfg != nil {
		return cfg, err
	}
	if meta, ok := m.(*providerMeta); ok {
		return meta.retry, nil
	}
	return nil, nil
}

// runWithRetry runs op once, and again while its error matches the active retry {} block.
func runWithRetry(ctx context.Context, d *schema.ResourceData, m interface{}, op func() error) error {
	cfg, err := activeRetryConfig(d, m)
	if err != nil {
		return err
	}
	err = op()
	if cfg == nil {
		return err
	}
	for retry := 0; retry < cfg.maxRetries && cfg.matches(err); retry++ {
		wait := backoffWait(cfg.interval, cfg.maxInterval, retry)
		log.Printf("[INFO] akeyless: retry %d/%d after %s: %v", retry+1, cfg.maxRetries, wait, err)
		if sleepErr := retrySleep(ctx, wait); sleepErr != nil {
			return err
		}
		err = op()
	}
	return err
}

func runDiagsWithRetry(ctx context.Context, d *schema.ResourceData, m interface{}, op func() diag.Diagnostics) diag.Diagnostics {
	var diags diag.Diagnostics
	err := runWithRetry(ctx, d, m, func() error {
		diags = op()
		return diagsError(diags)
	})
	if err != nil && !diags.HasError() {
		return append(diags, diag.FromErr(err)...)
	}
	return diags
}

func diagsError(diags diag.Diagnostics) error {
	var msgs []string
	for _, dg := range diags {
		if dg.Severity == diag.Error {
			msgs = append(msgs, strings.TrimSpace(dg.Summary+" "+dg.Detail))
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	return errors.New(strings.Join(msgs, "; "))
}

// backoffWait returns initial * 2^retry, capped at max.
func backoffWait(initial, max time.Duration, retry int) time.Duration {
	wait := initial
	for i := 0; i < retry && wait < max; i++ {
		wait *= 2
	}
	if wait > max {
		return max
	}
	return wait
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

// EnableResourceRetry adds the retry {} block to a resource and wraps its CRUD functions.
func EnableResourceRetry(r *schema.Resource) {
	if r == nil {
		return
	}
	if r.Schema == nil {
		r.Schema = map[string]*schema.Schema{}
	}
	if _, exists := r.Schema["retry"]; exists {
		return
	}
	r.Schema["retry"] = retrySchema("Retry this resource's operations when the error matches error_message_regex. Overrides the provider retry block. See the Customized Retry guide.")

	// Changing only retry {} must not recreate the item, so resources without
	// Update get one that just stores the new retry settings.
	if r.Update == nil && r.UpdateContext == nil {
		r.UpdateContext = func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
			return nil
		}
	}

	r.Create = wrapResourceFunc(r.Create)
	r.Read = wrapResourceFunc(r.Read)
	r.Update = wrapResourceFunc(r.Update)
	r.Delete = wrapResourceFunc(r.Delete)
	r.CreateContext = wrapResourceContextFunc(r.CreateContext)
	r.ReadContext = wrapResourceContextFunc(r.ReadContext)
	r.UpdateContext = wrapResourceContextFunc(r.UpdateContext)
	r.DeleteContext = wrapResourceContextFunc(r.DeleteContext)
}

func wrapResourceFunc(orig func(*schema.ResourceData, interface{}) error) func(*schema.ResourceData, interface{}) error {
	if orig == nil {
		return nil
	}
	return func(d *schema.ResourceData, m interface{}) error {
		return runWithRetry(context.Background(), d, m, func() error {
			return orig(d, m)
		})
	}
}

func wrapResourceContextFunc(orig func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics) func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
	if orig == nil {
		return nil
	}
	return func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		return runDiagsWithRetry(ctx, d, m, func() diag.Diagnostics {
			return orig(ctx, d, m)
		})
	}
}
