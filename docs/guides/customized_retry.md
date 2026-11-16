---
page_title: "Customized Retry"
subcategory: ""
description: |-
  Retry resource operations on busy or temporary errors.
---

# Customized Retry

By default the provider retries only connection errors (`EOF`, `connection reset by peer`,
`connection refused`), up to 3 attempts. Other errors, such as HTTP `429`, are returned as is.

You can add an optional `retry {}` block. When Create, Read, Update or Delete fails with an
error that matches `error_message_regex`, or with an HTTP status in `retry_on_status_codes`,
the whole operation runs again.

The block has the same fields in two places:

1. **Provider `retry {}`**: the default for all resources.
2. **Resource `retry {}`**: used for this resource only. It overrides the provider block.

| Provider `retry {}` | Resource `retry {}` | Result |
|---|---|---|
| not set | not set | No extra retry (default behavior) |
| set | not set | The provider block is used |
| not set | set | The resource block is used |
| set | set | Only the resource block is used |

## Fields

Set at least one of `error_message_regex` and `retry_on_status_codes`.

- `error_message_regex`: regular expressions matched against the full provider error, for example `can't create item: Too Many Requests`. A pattern anchored with `^` does not match that prefix.
- `retry_on_status_codes`: HTTP status codes of the failed API call, for example `[429, 503]`.
- `interval_seconds` (default `3`): wait before the first retry. The wait doubles on each retry.
- `max_interval_seconds` (default `180`): maximum wait between retries.
- `max_retries` (default `3`): maximum retries after the first attempt.

## Wait between retries

The wait starts at `interval_seconds` and doubles on each retry, up to `max_interval_seconds`.
When the server asks for a longer wait, with a `Retry-After` header or a
`will be released in Ns` message, the provider waits that long instead, but never more
than `max_interval_seconds`.

| Backoff | Server wait | `max_interval_seconds` | Wait |
|---|---|---|---|
| 10s | none | 60s | 10s |
| 10s | 15s | 60s | 15s |
| 40s | 5s | 60s | 40s |
| 10s | 300s | 60s | 60s |

## Provider-level retry

```terraform
provider "akeyless" {
  api_gateway_address = "https://api.akeyless.io"

  api_key_login {
    access_id  = var.access_id
    access_key = var.access_key
  }

  retry {
    retry_on_status_codes = [429, 502, 503, 504]
    error_message_regex   = ["Too Many Requests", "will be released in"]
    interval_seconds      = 10
    max_retries           = 3
  }
}
```

## Resource-level retry

```terraform
resource "akeyless_dynamic_secret_mysql" "example" {
  name        = "mysql-ds"
  target_name = "my-mysql-target"

  retry {
    error_message_regex  = ["Too Many Requests", "will be released in"]
    interval_seconds     = 10
    max_interval_seconds = 180
    max_retries          = 3
  }
}
```

To turn off the provider retry for one resource, set `max_retries = 0` and still set
`error_message_regex` or `retry_on_status_codes`. A `retry` block with only
`max_retries` is rejected.

Changing only the `retry` block never recreates the resource. The plan shows an in-place
update, but the provider only saves the new retry settings and does not call the update API.

**Note:** if a Create fails after the item was already created on the server, a rerun can
fail with an "already exists" error. Use regexes that match only busy or temporary errors.
