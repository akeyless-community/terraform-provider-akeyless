package akeyless

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

const (
	defaultRetryIntervalSeconds    = 3
	defaultRetryMaxIntervalSeconds = 180
	defaultRetryMaxRetries         = 3
	maxRetryIntervalSeconds        = 24 * 60 * 60
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
						ValidateFunc: validation.All(validation.StringIsNotEmpty, validation.StringIsValidRegExp),
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
					ValidateFunc: validation.IntBetween(1, maxRetryIntervalSeconds),
					Description:  "Wait before the first retry, in seconds. The wait doubles on each retry.",
				},
				"max_interval_seconds": {
					Type:         schema.TypeInt,
					Optional:     true,
					Default:      defaultRetryMaxIntervalSeconds,
					ValidateFunc: validation.IntBetween(1, maxRetryIntervalSeconds),
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
	intervalSeconds := m["interval_seconds"].(int)
	maxIntervalSeconds := m["max_interval_seconds"].(int)
	if maxIntervalSeconds < intervalSeconds {
		return nil, fmt.Errorf("retry.max_interval_seconds (%d) must be >= retry.interval_seconds (%d)", maxIntervalSeconds, intervalSeconds)
	}

	cfg := &retryConfig{
		statusCodes: map[int]bool{},
		interval:    time.Duration(intervalSeconds) * time.Second,
		maxInterval: time.Duration(maxIntervalSeconds) * time.Second,
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
		diags = append(diags, diag.FromErr(err)...)
	}
	return stripRetryMetadata(diags)
}

func diagsError(diags diag.Diagnostics) error {
	var msgs []string
	var status int
	var retryAfter time.Duration
	for _, dg := range diags {
		if dg.Severity != diag.Error {
			continue
		}
		diagStatus, diagRetryAfter := diagRetryMeta(dg.Detail)
		message := dg.Summary
		if diagStatus == 0 {
			message += " " + dg.Detail
		}
		msgs = append(msgs, strings.TrimSpace(message))
		if status == 0 {
			status, retryAfter = diagStatus, diagRetryAfter
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	err := errors.New(strings.Join(msgs, "; "))
	if status == 0 {
		return err
	}
	return common.APIErrorFromMetadata(status, retryAfter, err)
}

func diagRetryMeta(detail string) (int, time.Duration) {
	statusText, retryAfterText, hasRetryAfter := strings.Cut(strings.TrimPrefix(detail, "http_status="), " retry_after=")
	if statusText == detail {
		return 0, 0
	}
	status, err := strconv.Atoi(statusText)
	if err != nil {
		return 0, 0
	}
	if hasRetryAfter {
		retryAfter, _ := time.ParseDuration(retryAfterText)
		return status, retryAfter
	}
	return status, 0
}

func stripRetryMetadata(diags diag.Diagnostics) diag.Diagnostics {
	for i := range diags {
		if status, _ := diagRetryMeta(diags[i].Detail); status != 0 {
			diags[i].Detail = ""
		}
	}
	return diags
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
	r.Schema["retry"] = retrySchema("Retry this resource's operations when the error matches error_message_regex or the HTTP status is in retry_on_status_codes. Overrides the provider retry block. See the Customized Retry guide.")

	// Changing only retry {} must not recreate the item. Resources without an
	// Update reject other in-place changes.
	if r.Update == nil && r.UpdateContext == nil {
		r.UpdateContext = func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
			return diag.Errorf("this resource cannot be updated in place")
		}
	}

	// Plain CRUD functions become context functions, so Ctrl+C and timeouts stop the retry wait.
	r.CreateContext, r.Create = wrapCRUD(r.Create, r.CreateContext), nil
	r.ReadContext, r.Read = wrapRead(r.Read, r.ReadContext), nil
	r.UpdateContext, r.Update = skipRetryOnlyUpdate(wrapCRUD(r.Update, r.UpdateContext)), nil
	r.DeleteContext, r.Delete = wrapCRUD(r.Delete, r.DeleteContext), nil
}

func wrapCRUD(plain func(*schema.ResourceData, interface{}) error, withCtx func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics) func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
	if plain != nil {
		return wrapResourceFunc(plain)
	}
	return wrapResourceContextFunc(withCtx)
}

// wrapRead is wrapCRUD for Read. When the item is still not found (404) after any retries,
// it was deleted outside Terraform: remove it from state so the plan recreates it.
func wrapRead(plain func(*schema.ResourceData, interface{}) error, withCtx func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics) func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
	if plain == nil && withCtx == nil {
		return nil
	}
	return func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		// lastErr is the error of the last attempt, before it becomes diagnostics.
		var lastErr error
		var diags diag.Diagnostics
		if plain != nil {
			diags = wrapResourceFunc(func(d *schema.ResourceData, m interface{}) error {
				lastErr = plain(d, m)
				return lastErr
			})(ctx, d, m)
		} else {
			diags = wrapResourceContextFunc(func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
				readDiags := withCtx(ctx, d, m)
				lastErr = diagsError(readDiags)
				return readDiags
			})(ctx, d, m)
		}

		if isNotFound(lastErr) {
			log.Printf("[WARN] akeyless: %s not found, removing it from state", d.Id())
			d.SetId("")
			return nil
		}
		return diags
	}
}

// isNotFound reports whether err is an HTTP 404 from the Akeyless API.
func isNotFound(err error) bool {
	var apiErr *common.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusNotFound
	}
	// Some reads return the SDK error as is. Its message is the HTTP status, for example "404 Not Found".
	var sdkErr *akeyless_api.GenericOpenAPIError
	return errors.As(err, &sdkErr) && strings.HasPrefix(sdkErr.Error(), "404 ")
}

// skipRetryOnlyUpdate stores a change of only the retry block without calling the update API.
func skipRetryOnlyUpdate(update func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics) func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
	return func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		if !d.HasChangeExcept("retry") {
			return nil
		}
		return update(ctx, d, m)
	}
}

func wrapResourceFunc(orig func(*schema.ResourceData, interface{}) error) func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics {
	return func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		return diag.FromErr(runWithRetry(ctx, d, m, func() error {
			return orig(d, m)
		}))
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
