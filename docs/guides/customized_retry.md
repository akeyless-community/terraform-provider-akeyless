# Customized Retry

By default the provider retries only connection errors (`EOF`, `connection reset by peer`,
`connection refused`), up to 3 attempts. Busy responses such as HTTP `429` are returned as errors.

Two optional settings add more retries. Both are off unless you set them.

1. **Provider `maximum_busy_retry_attempts`**: retries every API call that gets a busy response.
2. **Resource `retry {}`**: reruns one resource's operation when its error matches a regex.
   It runs after the provider-level retries are used up.

## Provider-level retry

```terraform
provider "akeyless" {
  api_gateway_address = "https://api.akeyless.io"

  api_key_login {
    access_id  = var.access_id
    access_key = var.access_key
  }

  maximum_busy_retry_attempts = 3
}
```

When `maximum_busy_retry_attempts` is greater than `0`, the provider retries:

- HTTP statuses `429`, `500`, `502`, `503`, `504`
- SaaS rate-limit errors, also when wrapped in another status (for example a `403` with
  `Too Many Requests` or `will be released in Ns` in the body)

The wait before each retry is:

1. The `Retry-After` header, when present
2. The delay in `will be released in Ns`, when present
3. Otherwise 1s, doubled on each retry, up to 30s

`401` and `403` without a rate-limit message are not retried.

You can also set it with the `AKEYLESS_MAXIMUM_BUSY_RETRY_ATTEMPTS` environment variable.

## Resource-level retry

Every resource supports an optional `retry {}` block. When Create, Read, Update or Delete
fails with an error that matches `error_message_regex`, the whole operation runs again.

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

- `error_message_regex` (required): regular expressions matched against the error message.
- `interval_seconds` (default `10`): wait before the first retry. The wait doubles on each retry.
- `max_interval_seconds` (default `180`): maximum wait between retries.
- `max_retries` (default `3`): maximum retries after the first attempt.

Changing only the `retry` block never recreates the resource.

**Note:** if a Create fails after the item was already created on the server, a rerun can
fail with an "already exists" error. Use regexes that match only busy or temporary errors.
