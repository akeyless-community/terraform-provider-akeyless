package akeyless

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

const (
	defaultRetryIntervalSeconds    = 3
	defaultRetryMaxIntervalSeconds = 180
	defaultRetryMaxRetries         = 3
)

// retrySleep is replaced in tests.
var retrySleep = sleepContext

// retryTriggerFields must have at least one value in a retry {} block.
var retryTriggerFields = []string{"retry.0.error_message_regex", "retry.0.retry_on_status_codes"}

// releaseDelayRE reads the delay from SaaS rate-limit errors, for example "will be released in 14.15s".
var releaseDelayRE = regexp.MustCompile(`(?i)will be released in\s+([0-9]+(?:\.[0-9]+)?)\s*s`)

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
					Type:         schema.TypeList,
					Optional:     true,
					MinItems:     1,
					AtLeastOneOf: retryTriggerFields,
					Description:  "Regular expressions matched against the error message. If any matches, the operation is retried.",
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: validation.StringIsValidRegExp,
					},
				},
				"retry_on_status_codes": {
					Type:         schema.TypeList,
					Optional:     true,
					MinItems:     1,
					AtLeastOneOf: retryTriggerFields,
					Description:  "HTTP status codes of the failed API call that trigger a retry, for example 429 or 503.",
					Elem: &schema.Schema{
						Type:         schema.TypeInt,
						ValidateFunc: validation.IntBetween(100, 599),
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
	statusCodes map[int]bool
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
		statusCodes: map[int]bool{},
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
	for _, code := range m["retry_on_status_codes"].([]interface{}) {
		cfg.statusCodes[code.(int)] = true
	}
	return cfg, nil
}

func (c *retryConfig) matches(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *common.APIError
	if errors.As(err, &apiErr) && c.statusCodes[apiErr.StatusCode] {
		return true
	}
	for _, re := range c.regexes {
		if re.MatchString(err.Error()) {
			return true
		}
	}
	return false
}

// wait returns the backoff for this retry, or the server's Retry-After when it is longer,
// capped at maxInterval.
func (c *retryConfig) wait(retry int, err error) time.Duration {
	wait := backoffWait(c.interval, c.maxInterval, retry)
	if after := serverRetryAfter(err); after > wait {
		wait = min(after, c.maxInterval)
	}
	return wait
}

// serverRetryAfter returns the Retry-After header, or the "will be released in Ns" delay.
func serverRetryAfter(err error) time.Duration {
	var apiErr *common.APIError
	if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
		return apiErr.RetryAfter
	}
	if m := releaseDelayRE.FindStringSubmatch(err.Error()); len(m) == 2 {
		if sec, parseErr := strconv.ParseFloat(m[1], 64); parseErr == nil {
			return time.Duration(sec * float64(time.Second))
		}
	}
	return 0
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
		wait := cfg.wait(retry, err)
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
