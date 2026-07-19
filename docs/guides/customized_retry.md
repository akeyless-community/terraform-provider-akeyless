# Customized Retry

The Akeyless Terraform provider retries transient failures at two layers:

1. **Provider HTTP transport** (all API calls) — connection errors + busy HTTP statuses by default
2. **Resource `retry`** (optional) — when set on a resource, **overrides** provider HTTP retry for that resource's CRUD calls

Only one layer runs per resource operation: resource `retry {}` wins over provider `retry {}`.

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
    retry_on_messages   = [".*temporary.*"]
  }
}
```

When `retry {}` is omitted, the same defaults apply (`max_retries = 3`, statuses above, etc.).

Plain **401** / **403** without a rate-limit body are not retried.

Notes:

- `retry_on_messages` are error-message texts, matched as **regular expressions** (plain text works; regex is supported). Note that regex metacharacters (`.`, `(`, `*`, ...) in the text are interpreted as regex.
- Passing an empty `retry_on_status_codes = []` keeps the defaults (429/5xx); it does not disable status-code retries.
- Wrapped SaaS rate-limit bodies are always retried and cannot be turned off.

### Environment overrides

- `AKEYLESS_MAX_RETRIES`
- `AKEYLESS_RETRY_INTERVAL_SECONDS`
- `AKEYLESS_MAX_BACKOFF_SECONDS`
- `AKEYLESS_RETRY_MULTIPLIER`

## Resource-level retry

When a resource sets `retry {}`, its API calls retry at the HTTP transport level using
these settings **instead of** the provider defaults (the same request-level mechanism as
provider retry, just per-resource). The retry happens on individual API calls, so a create
is never re-run as a whole.

```terraform
resource "akeyless_dynamic_secret_aws" "example" {
  name        = "aws-ds"
  target_name = akeyless_target_aws.example.name

  retry {
    interval_seconds     = 10
    max_interval_seconds = 180
    multiplier           = 1.5
    max_retries          = 3
  }
}
```

Like provider retry, connection errors (`EOF`, `connection reset by peer`,
`connection refused`), busy HTTP statuses (`429`, `5xx`), and wrapped SaaS rate-limit
bodies are always retried. `retry_on_messages` adds extra error-message matches on top
(matched as regular expressions):

```terraform
  retry {
    retry_on_messages = [".*temporary.*"]
    max_retries       = 5
  }
```

**Note:** on resources without an update operation (create-only), the `retry` block is
`ForceNew` — changing any retry setting triggers a destroy + recreate of the item. This is
a Terraform SDK constraint for create-only resources. Set retry once at creation, or expect
recreation when you change it.
