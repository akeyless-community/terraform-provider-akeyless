# Ephemeral resources

Ephemeral resources require Terraform 1.11 or later. Their values are available
during a Terraform operation but are not stored in state.

Supported ephemeral resources:

- `akeyless_dynamic_secret`
- `akeyless_static_secret`
- `akeyless_rotated_secret`
- `akeyless_certificate`
- `akeyless_pki_certificate`
- `akeyless_ssh_certificate`
- `akeyless_target_details`

Example:

```hcl
ephemeral "akeyless_static_secret" "db_password" {
  path = "/my-secret"
}
```

Use an ephemeral value only with another ephemeral-compatible or write-only
argument. Terraform does not allow it in outputs or normal state-persisted
arguments.
