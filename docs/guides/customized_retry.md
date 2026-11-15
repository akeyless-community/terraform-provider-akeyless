# Customized Retry

By default the provider retries only connection errors (`EOF`, `connection reset by peer`,
`connection refused`), up to 3 attempts. Other errors, such as HTTP `429`, are returned as is.

You can add an optional `retry {}` block. When Create, Read, Update or Delete fails with an
error that matches `error_message_regex`, the whole operation runs again.

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

- `error_message_regex` (required): regular expressions matched against the error message.
- `interval_seconds` (default `10`): wait before the first retry. The wait doubles on each retry.
- `max_interval_seconds` (default `180`): maximum wait between retries.
- `max_retries` (default `3`): maximum retries after the first attempt.

## Provider-level retry

```terraform
provider "akeyless" {
  api_gateway_address = "https://api.akeyless.io"

  api_key_login {
    access_id  = var.access_id
    access_key = var.access_key
  }

  retry {
    error_message_regex = ["Too Many Requests", "will be released in"]
    interval_seconds    = 10
    max_retries         = 3
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

To turn off the provider retry for one resource, set `max_retries = 0` in its `retry {}` block.

Changing only the `retry` block never recreates the resource.

**Note:** if a Create fails after the item was already created on the server, a rerun can
fail with an "already exists" error. Use regexes that match only busy or temporary errors.
