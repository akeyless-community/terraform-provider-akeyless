# Ephemeral resources

Ephemeral resources require Terraform 1.10 or later. Write-only (`*_wo`)
arguments require Terraform 1.11 or later. The provider uses plugin protocol
v6, so Terraform 0.15.4 or later is required for any configuration.

Ephemeral values are available during a Terraform operation but are not stored
in state.

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

`akeyless_dynamic_secret` creates new credentials every time it is opened.
Terraform opens it on both plan and apply, so each run creates two
credentials. Terraform does not revoke them; they expire with the dynamic
secret TTL.
