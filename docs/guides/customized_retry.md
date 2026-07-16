# Customized Retry

The Akeyless Terraform provider retries transient failures at two layers:

1. **Provider HTTP transport** (all API calls) — connection errors + busy HTTP statuses by default
2. **Resource `retry`** (optional) — message-regex retries after provider retries are exhausted

## Provider-level retry (default on)

By default the provider retries:

- Connection errors: `EOF`, `connection reset by peer`, `connection refused`
- HTTP statuses: `429`, `500`, `502`, `503`, `504` (see `busyHTTPStatusCodes` in code)
- Wrapped SaaS rate-limit bodies (e.g. outer `403` with `429 Too Many Requests` / `will be released in Ns`)

Backoff order:

1. `Retry-After` header
2. SaaS body release delay (`will be released in Ns`)
3. Exponential backoff

Optional knobs:

```terraform
provider "akeyless" {
  api_gateway_address = "https://api.akeyless.io"

  api_key_login {
    access_id  = var.access_id
    access_key = var.access_key
  }

  retry {
    max_retries           = 5
    retry_on_status_codes = [429, 500, 502, 503, 504]
    interval_seconds      = 2
    max_backoff_seconds   = 60
    multiplier            = 1.5
    error_message_regex   = [".*temporary.*"]
  }
}
```

When `retry {}` is omitted, the same defaults apply (`max_retries = 3`, statuses above, etc.).

Plain **401** / **403** without a rate-limit body are not retried.

### Environment overrides

- `AKEYLESS_MAX_RETRIES`
- `AKEYLESS_RETRY_INTERVAL_SECONDS`
- `AKEYLESS_MAX_BACKOFF_SECONDS`
- `AKEYLESS_RETRY_MULTIPLIER`

## Resource-level retry

After provider HTTP retries are exhausted, any resource can retry again when the error message matches configured regexes.

```terraform
resource "akeyless_dynamic_secret_aws" "example" {
  name        = "aws-ds"
  target_name = akeyless_target_aws.example.name

  retry {
    error_message_regex  = [".*Too Many Requests.*", ".*will be released in.*"]
    interval_seconds     = 10
    max_interval_seconds = 180
    multiplier           = 1.5
    max_retries          = 3
  }
}
```

`error_message_regex` is required when a resource `retry` block is set.

Resource retry runs **after** provider HTTP retries.
