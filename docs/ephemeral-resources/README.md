# Ephemeral resources

Ephemeral resources require Terraform 1.10 or later. Write-only (`*_wo`)
arguments require Terraform 1.11 or later. The provider uses plugin protocol
v6, so Terraform 0.15.4 or later is required for any configuration.

Ephemeral values are available during a Terraform operation but are not stored
in state.

See one page per resource in this directory (generated with `go generate`).

`akeyless_dynamic_secret` creates new credentials every time it is opened.
Terraform opens it on both plan and apply, so each run creates two
credentials. Terraform does not revoke them; they expire with the dynamic
secret TTL.

`akeyless_pki_certificate` and `akeyless_ssh_certificate` issue a new
certificate on every Open. Terraform calls Open on plan and again on apply, so
each plan produces a certificate that apply does not use. Terraform does not
revoke the plan-time certificate; manage lifetime through TTL where supported.

Example:

```hcl
ephemeral "akeyless_static_secret" "db_password" {
  path = "/my-secret"
}
```

Use an ephemeral value only with another ephemeral-compatible or write-only
argument. Terraform does not allow it in outputs or normal state-persisted
arguments.