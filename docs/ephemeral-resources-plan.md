# Ephemeral Resources & Write-Only Arguments Implementation Plan

**Ticket:** [ASM-15765](https://akeyless.atlassian.net/browse/ASM-15765)  
**Author:** Aviv  
**Date:** July 2026  
**Updated:** July 29, 2026 — Added Write-Only arguments scope

---

## Executive Summary

Add support for Terraform 1.10+ **ephemeral resources** and **write-only arguments** to the Akeyless provider:

1. **Ephemeral Resources** — Allow users to fetch secrets (dynamic secrets, static secrets, certificates) **without persisting them in Terraform state**
2. **Write-Only Arguments** — Allow users to pass sensitive inputs (passwords, API keys) to resources **without persisting them in state**

---

## Table of Contents

1. [Goal](#goal)
2. [Problem Statement](#problem-statement)
3. [Two Features: Ephemeral vs Write-Only](#two-features-ephemeral-vs-write-only)
4. [Background: What is terraform-plugin-mux?](#background-what-is-terraform-plugin-mux)
5. [Design Principles](#design-principles)
6. [Architecture](#architecture)
7. [File Structure](#file-structure)
8. [Shared Client Package](#shared-client-package)
9. [Ephemeral Resource Pattern](#ephemeral-resource-pattern)
10. [Write-Only Arguments Pattern](#write-only-arguments-pattern)
11. [Resources to Implement](#resources-to-implement)
12. [Implementation Steps](#implementation-steps)
13. [Testing Strategy](#testing-strategy)
14. [Rollout Plan](#rollout-plan)
15. [What We Are NOT Doing](#what-we-are-not-doing)
16. [Success Criteria](#success-criteria)
17. [Open Questions](#open-questions)
18. [Estimated Effort](#estimated-effort)

---

## Goal

Allow users to fetch secrets from Akeyless during a Terraform run **without persisting them in state**.

```hcl
ephemeral "akeyless_dynamic_secret" "db_creds" {
  path = "/mysql-ds"
}

resource "aws_db_instance" "main" {
  password = ephemeral.akeyless_dynamic_secret.db_creds.value.password
}
```

The secret value is used to create the database but is **never written to `terraform.tfstate`**.

---

## Problem Statement

Today, when using data sources like `data "akeyless_dynamic_secret"`, the secret value is stored in `terraform.tfstate`:

```json
{
  "type": "akeyless_dynamic_secret",
  "name": "secret",
  "instances": [
    {
      "attributes": {
        "path": "/LDAP-DS",
        "value": "{\"user\":\"tmp.p-16.23ihP\",\"password\":\"SPU1x=c+3HV=\"}"
      }
    }
  ]
}
```

Even though `value` is marked `sensitive`, it is still persisted. Customers with compliance requirements (SOC2, PCI-DSS, etc.) cannot accept secrets stored outside Akeyless.

Terraform 1.10+ introduced **ephemeral resources** — values that exist only during the run and are never written to state. The Akeyless provider must implement this capability.

---

## Two Features: Ephemeral vs Write-Only

The ticket asks for **both** features. Here's the difference:

| Feature | Direction | Problem It Solves | Requires |
|---------|-----------|-------------------|----------|
| **Ephemeral Resources** | Akeyless → Terraform (output) | Fetched secrets saved in state | Framework + Mux |
| **Write-Only Arguments** | Terraform → Akeyless (input) | Input passwords saved in state | SDK v2 changes only |

### Visual Comparison

```
EPHEMERAL (output direction):
┌──────────────┐                    ┌──────────────┐
│   Akeyless   │ ──── GET creds ──→ │  Terraform   │
│              │                    │  (use only,  │
│              │                    │  don't save) │
└──────────────┘                    └──────────────┘

WRITE-ONLY (input direction):
┌──────────────┐                    ┌──────────────┐
│   Akeyless   │ ←── POST password ─│  Terraform   │
│   (stores    │                    │  (send only, │
│    secret)   │                    │  don't save) │
└──────────────┘                    └──────────────┘
```

### Example: Ephemeral (data_source replacement)

```hcl
# BEFORE: Data source — password saved in state
data "akeyless_dynamic_secret" "db" {
  path = "/mysql-ds"
}
# State contains: {"value": "{\"password\":\"secret123\"}"}

# AFTER: Ephemeral — password NOT saved
ephemeral "akeyless_dynamic_secret" "db" {
  path = "/mysql-ds"
}
# State contains: nothing
```

### Example: Write-Only (resource input)

```hcl
# BEFORE: Resource — mysql_password saved in state
resource "akeyless_dynamic_secret_mysql" "db" {
  name           = "/my-ds"
  mysql_password = "secret123"
}
# State contains: {"mysql_password": "secret123"}

# AFTER: Write-only — mysql_password NOT saved
resource "akeyless_dynamic_secret_mysql" "db" {
  name                      = "/my-ds"
  mysql_password_wo         = "secret123"
  mysql_password_wo_version = 1
}
# State contains: {"mysql_password_wo": null, "mysql_password_wo_version": 1}
```

### Implementation Complexity

| Feature | Requires Mux? | Changes to Existing Files? | New Files? |
|---------|--------------|---------------------------|------------|
| **Ephemeral** | ✅ Yes | ❌ No | ✅ Yes — new Framework code |
| **Write-Only** | ❌ No | ✅ Yes — add `*_wo` fields | ❌ No |

---

## Background: What is terraform-plugin-mux?

### The Problem

The Akeyless provider is built on **Terraform Plugin SDK v2**. SDK v2 does not support ephemeral resources — that feature requires the **Terraform Plugin Framework**.

Migrating the entire provider from SDK v2 to Framework would be a massive effort (150+ resources).

### The Solution

`terraform-plugin-mux` lets us run **two provider engines in one binary**:

- **SDK v2 provider** — handles all existing resources and data sources (unchanged)
- **Framework provider** — handles only the new ephemeral resources

Think of it like a restaurant with two kitchens:
- Kitchen A (SDK v2) makes the existing menu
- Kitchen B (Framework) makes the new dishes
- One front door (the provider binary) — Terraform doesn't know there are two kitchens

### Example

```go
// main.go — before (SDK v2 only)
func main() {
    plugin.Serve(&plugin.ServeOpts{
        ProviderFunc: func() *schema.Provider {
            return akeyless.Provider()
        },
    })
}
```

```go
// main.go — after (muxed provider)
func main() {
    ctx := context.Background()

    // Existing SDK v2 provider
    sdkv2Provider := akeyless.Provider()

    // New Framework provider (ephemeral resources only)
    frameworkProvider := framework.NewProvider()

    // Combine both into one server
    muxServer, _ := tf6muxserver.NewMuxServer(ctx,
        func() tfprotov6.ProviderServer {
            return tf5to6server.UpgradeServer(
                schema.NewGRPCProviderServer(sdkv2Provider),
            )
        },
        providerserver.NewProtocol6(frameworkProvider),
    )

    tf6server.Serve(
        "registry.terraform.io/akeyless-community/akeyless",
        muxServer.ProviderServer,
    )
}
```

**What happens at runtime:**

| User writes | Mux routes to |
|-------------|---------------|
| `resource "akeyless_static_secret"` | SDK v2 |
| `data "akeyless_dynamic_secret"` | SDK v2 |
| `ephemeral "akeyless_dynamic_secret"` | Framework |

Same binary, same authentication, transparent to the user.

---

## Design Principles

1. **Minimal footprint** — Add only what is needed; do not refactor existing SDK v2 code
2. **Single source of truth** — Share authentication and client logic between SDK v2 and Framework
3. **Convention over configuration** — Each ephemeral resource follows the same pattern
4. **Progressive delivery** — Ship one ephemeral resource first, expand later

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Terraform CLI                        │
│                   (Protocol v6)                         │
└────────────────────────┬────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
┌─────────────────────┐       ┌─────────────────────────┐
│   SDK v2 Provider   │       │   Framework Provider    │
│  (existing code)    │       │   (new ephemeral only)  │
│                     │       │                         │
│  - Resources        │       │  - EphemeralResources   │
│  - Data Sources     │       │                         │
└─────────┬───────────┘       └───────────┬─────────────┘
          │                               │
          └───────────┬───────────────────┘
                      ▼
          ┌───────────────────────┐
          │   internal/client     │
          │   (shared package)    │
          │                       │
          │  - Auth logic         │
          │  - API client         │
          │  - Token management   │
          └───────────────────────┘
                      │
                      ▼
          ┌───────────────────────┐
          │     Akeyless API      │
          └───────────────────────┘
```

**Key point:** Both providers share the same authentication code. We extract it to a common package.

---

## File Structure

```
terraform-provider-akeyless/
├── main.go                          # UPDATED: mux SDK v2 + Framework
├── go.mod                           # ADD: terraform-plugin-framework, terraform-plugin-mux
│
├── akeyless/                        # EXISTING: SDK v2 code (minimal changes)
│   ├── provider.go                  # UPDATE: use internal/client for auth
│   ├── resource_*.go                # UNCHANGED
│   ├── data_source_*.go             # UNCHANGED
│   └── common/
│       └── utils.go                 # UNCHANGED
│
└── internal/
    ├── client/                      # NEW: Shared Akeyless client
    │   ├── client.go                # Client struct + NewClient()
    │   └── auth.go                  # Auth logic (extracted from provider.go)
    │
    └── framework/                   # NEW: Framework provider
        ├── provider.go              # Framework provider definition
        │
        └── ephemeral/               # Ephemeral resources
            ├── common.go            # Shared helper for all ephemeral resources
            ├── dynamic_secret.go    # akeyless_dynamic_secret
            ├── static_secret.go     # akeyless_static_secret
            ├── pki_certificate.go   # akeyless_pki_certificate
            └── ...                  # Other secret types
```

---

## Shared Client Package

Extract authentication logic so both providers use the same code.

```go
// internal/client/client.go
package client

import (
    "context"
    akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
)

// Client holds an authenticated Akeyless API client
type Client struct {
    API   *akeyless_api.V2ApiService
    Token string
}

// Config holds provider configuration
type Config struct {
    APIGatewayAddress string
    Auth              AuthConfig
}

// AuthConfig holds authentication details
type AuthConfig struct {
    Type      string // "api_key", "aws_iam", "gcp", "azure_ad", "jwt", "cert", "token"
    AccessID  string
    AccessKey string
    // ... other auth fields
}

// New creates an authenticated client
func New(ctx context.Context, cfg Config) (*Client, error) {
    api := newAPIService(cfg.APIGatewayAddress)
    token, err := authenticate(ctx, api, cfg.Auth)
    if err != nil {
        return nil, err
    }
    return &Client{API: api, Token: token}, nil
}
```

The existing SDK v2 `provider.go` will call this package instead of inline auth logic.

---

## Ephemeral Resource Pattern

Each ephemeral resource follows the same structure:

```go
// internal/framework/ephemeral/dynamic_secret.go
package ephemeral

import (
    "context"
    "github.com/hashicorp/terraform-plugin-framework/ephemeral"
    "github.com/akeylesslabs/terraform-provider-akeyless/internal/client"
)

// Ensure interface compliance
var _ ephemeral.EphemeralResource = &DynamicSecretEphemeral{}

type DynamicSecretEphemeral struct {
    client *client.Client
}

func NewDynamicSecret() ephemeral.EphemeralResource {
    return &DynamicSecretEphemeral{}
}

func (r *DynamicSecretEphemeral) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
    resp.TypeName = req.ProviderTypeName + "_dynamic_secret"
}

func (r *DynamicSecretEphemeral) Schema(ctx context.Context, req ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
    resp.Schema = schema.Schema{
        Description: "Fetches a dynamic secret value without storing it in state",
        Attributes: map[string]schema.Attribute{
            "path": schema.StringAttribute{
                Required:    true,
                Description: "The path where the dynamic secret is stored",
            },
            "value": schema.StringAttribute{
                Computed:    true,
                Sensitive:   true,
                Description: "The secret value (not stored in state)",
            },
        },
    }
}

func (r *DynamicSecretEphemeral) Configure(ctx context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
    // Get client from provider
    if req.ProviderData == nil {
        return
    }
    r.client = req.ProviderData.(*client.Client)
}

func (r *DynamicSecretEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
    // 1. Read inputs
    var path string
    req.Config.GetAttribute(ctx, path.Path("path"), &path)

    // 2. Call Akeyless API
    body := akeyless_api.GetDynamicSecretValue{
        Name:  path,
        Token: &r.client.Token,
    }
    result, _, err := r.client.API.GetDynamicSecretValue(ctx).Body(body).Execute()
    if err != nil {
        resp.Diagnostics.AddError("Failed to get dynamic secret", err.Error())
        return
    }

    // 3. Set result (not stored in state)
    resp.Result.SetAttribute(ctx, path.Path("value"), result)
}

func (r *DynamicSecretEphemeral) Renew(ctx context.Context, req ephemeral.RenewRequest, resp *ephemeral.RenewResponse) {
    // No-op for Akeyless secrets — they are fetched fresh each time
}

func (r *DynamicSecretEphemeral) Close(ctx context.Context, req ephemeral.CloseRequest, resp *ephemeral.CloseResponse) {
    // No cleanup needed
}
```

---

## Write-Only Arguments Pattern

Write-only arguments are simpler — they work with existing SDK v2 code.

### Schema Changes

For each sensitive input field, add two new fields:

```go
// BEFORE: resource_dynamic_secret_mysql.go
"mysql_password": {
    Type:        schema.TypeString,
    Optional:    true,
    Sensitive:   true,
    Description: "MySQL password",
},

// AFTER: Add write-only variant
"mysql_password": {
    Type:          schema.TypeString,
    Optional:      true,
    Sensitive:     true,
    Description:   "MySQL password",
    ConflictsWith: []string{"mysql_password_wo"},
},
"mysql_password_wo": {
    Type:          schema.TypeString,
    Optional:      true,
    WriteOnly:     true,
    RequiredWith:  []string{"mysql_password_wo_version"},
    ConflictsWith: []string{"mysql_password"},
    Description:   "MySQL password (write-only, not stored in state)",
},
"mysql_password_wo_version": {
    Type:         schema.TypeInt,
    Optional:     true,
    RequiredWith: []string{"mysql_password_wo"},
    Description:  "Version trigger for mysql_password_wo updates",
},
```

### CRUD Logic Changes

```go
// In Create/Update function
func resourceDynamicSecretMysqlCreate(d *schema.ResourceData, m interface{}) error {
    // ...
    
    // Handle both regular and write-only password
    var mysqlPassword string
    if v, ok := d.GetOk("mysql_password"); ok {
        mysqlPassword = v.(string)
    } else if v, ok := d.GetOk("mysql_password_wo"); ok {
        mysqlPassword = v.(string)
    }
    
    // Use mysqlPassword in API call...
}
```

### Write-Only Resources to Update

| Resource | Sensitive Fields to Add `*_wo` |
|----------|-------------------------------|
| `resource_dynamic_secret_mysql` | `mysql_password` |
| `resource_dynamic_secret_ldap` | `bind_dn_password` |
| `resource_dynamic_secret_mssql` | `mssql_password` |
| `resource_dynamic_secret_postgresql` | `postgresql_password` |
| `resource_dynamic_secret_oracle` | `oracle_password` |
| `resource_dynamic_secret_cassandra` | `cassandra_password` |
| `resource_dynamic_secret_redis` | `password` |
| `resource_dynamic_secret_mongo` | `mongodb_password` |
| `resource_target_db` | `pwd` |
| `resource_target_aws` | `secret_access_key` |
| `resource_target_azure` | `client_secret` |
| `resource_target_gcp` | `gcp_sa_email` (service account key) |
| `resource_rotated_secret_*` | `password`, `api_key` |
| `resource_static_secret` | `value` |

---

## Resources to Implement

### Part A: Ephemeral Resources (NEW files in Framework)

| Priority | Ephemeral Resource | Akeyless API | Description |
|----------|-------------------|--------------|-------------|
| **P0** | `akeyless_dynamic_secret` | `GetDynamicSecretValue` | Dynamic secrets (LDAP, DB, cloud, etc.) |
| **P0** | `akeyless_static_secret` | `GetSecretValue` | Static secrets |
| **P1** | `akeyless_secret` | `GetSecretValue` | Generic secret (alias) |
| **P1** | `akeyless_rotated_secret` | `GetRotatedSecretValue` | Rotated secrets |
| **P1** | `akeyless_pki_certificate` | `GetPKICertificate` | PKI certificates |
| **P1** | `akeyless_ssh_certificate` | `GetSSHCertificate` | SSH certificates |
| **P1** | `akeyless_certificate` | `GetCertificateValue` | Certificate + private key |
| **P2** | `akeyless_kube_exec_creds` | `GetKubeExecCreds` | Kubernetes credentials |

### Part B: Write-Only Arguments (CHANGES to existing SDK v2 files)

| Priority | Existing Resource | Fields to Add `*_wo` Variant |
|----------|-------------------|------------------------------|
| **P0** | `resource_dynamic_secret_mysql` | `mysql_password` |
| **P0** | `resource_dynamic_secret_ldap` | `bind_dn_password` |
| **P0** | `resource_static_secret` | `value` |
| **P1** | `resource_dynamic_secret_mssql` | `mssql_password` |
| **P1** | `resource_dynamic_secret_postgresql` | `postgresql_password` |
| **P1** | `resource_dynamic_secret_oracle` | `oracle_password` |
| **P1** | `resource_dynamic_secret_redis` | `password` |
| **P1** | `resource_dynamic_secret_mongo` | `mongodb_password` |
| **P1** | `resource_dynamic_secret_cassandra` | `cassandra_password` |
| **P1** | `resource_target_db` | `pwd` |
| **P1** | `resource_target_aws` | `secret_access_key` |
| **P1** | `resource_target_azure` | `client_secret` |
| **P2** | All `resource_rotated_secret_*` | `password`, `api_key`, etc. |

**P0** = Ship first. **P1** = Fast follow. **P2** = When requested.

---

## Implementation Steps

### Phase 1 — Foundation: Ephemeral Resources

| Step | Task | Details |
|------|------|---------|
| 1.1 | Add dependencies | `terraform-plugin-framework`, `terraform-plugin-mux` |
| 1.2 | Create `internal/client/` | Extract auth logic from `akeyless/provider.go` |
| 1.3 | Update SDK v2 provider | Call `internal/client` for authentication |
| 1.4 | Create Framework provider | `internal/framework/provider.go` with same auth schema |
| 1.5 | Wire up mux | Update `main.go` to serve both providers |
| 1.6 | Add `akeyless_dynamic_secret` ephemeral | First ephemeral resource |
| 1.7 | Add `akeyless_static_secret` ephemeral | Second ephemeral resource |
| 1.8 | Write tests | Unit + acceptance tests for ephemeral |
| 1.9 | Write docs | Usage examples, migration guide |

### Phase 2 — Write-Only Arguments (Can Run in Parallel)

| Step | Task | Details |
|------|------|---------|
| 2.1 | Add `mysql_password_wo` | `resource_dynamic_secret_mysql.go` |
| 2.2 | Add `bind_dn_password_wo` | `resource_dynamic_secret_ldap.go` |
| 2.3 | Add `value_wo` | `resource_static_secret.go` |
| 2.4 | Add remaining P1 write-only fields | Database dynamic secrets |
| 2.5 | Write tests | Acceptance tests for write-only |
| 2.6 | Write docs | Usage examples |

### Phase 3 — Expand Coverage

| Step | Task |
|------|------|
| 3.1 | Add remaining P1 ephemeral resources |
| 3.2 | Add remaining P1 write-only fields |
| 3.3 | Update CI matrix for Terraform 1.10+ |

**Note:** Phases 1 and 2 can run in parallel because:
- Ephemeral = New Framework files (no conflicts)
- Write-Only = Changes to existing SDK v2 files (no conflicts with Framework)

---

## Testing Strategy

### Unit Tests

```go
func TestDynamicSecretEphemeral_Open(t *testing.T) {
    // Mock Akeyless API
    // Verify correct API call
    // Verify response mapping
}
```

### Acceptance Tests

```go
func TestAccEphemeralDynamicSecret_basic(t *testing.T) {
    resource.Test(t, resource.TestCase{
        ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
        Steps: []resource.TestStep{
            {
                Config: `
                    ephemeral "akeyless_dynamic_secret" "test" {
                        path = "/test-dynamic-secret"
                    }

                    output "secret_value" {
                        value     = ephemeral.akeyless_dynamic_secret.test.value
                        sensitive = true
                    }
                `,
                // Verify output exists but state is empty
            },
        },
    })
}
```

### CI Matrix

| Terraform Version | What is Tested |
|-------------------|----------------|
| 1.5.x | SDK v2 resources and data sources only |
| 1.10+ | Full suite including ephemeral resources |

---

## Rollout Plan

| Step | Action | Risk |
|------|--------|------|
| 1 | Merge foundation + `akeyless_dynamic_secret` | Low — existing code unchanged |
| 2 | Release as minor version (e.g., v1.X.0) | Low — new feature, no breaking changes |
| 3 | Announce in release notes | — |
| 4 | Gather feedback from early adopters | — |
| 5 | Add remaining ephemeral resources | Low — follows established pattern |

---

## What We Are NOT Doing

| Scope | Reason |
|-------|--------|
| Migrating existing resources to Framework | Too much effort, no benefit |
| Changing data source behavior | Backward compatibility |
| Refactoring SDK v2 code | Only extracting auth to shared package |
| Removing data sources | Users may still want state-stored secrets |
| Removing original password fields | Backward compatibility — keep both `password` and `password_wo` |

---

## Success Criteria

### Ephemeral Resources
- [ ] `ephemeral "akeyless_dynamic_secret"` works with Terraform 1.10+
- [ ] `ephemeral "akeyless_static_secret"` works with Terraform 1.10+
- [ ] Secret value does **not** appear in `terraform.tfstate`
- [ ] Secret value does **not** appear in `terraform plan` output (shown as sensitive)

### Write-Only Arguments
- [ ] `mysql_password_wo` field works in `akeyless_dynamic_secret_mysql`
- [ ] Write-only fields show as `null` in `terraform.tfstate`
- [ ] Updating `*_wo_version` triggers resource update

### General
- [ ] Existing SDK v2 resources and data sources continue to work unchanged
- [ ] CI passes for both old (1.5+) and new (1.10+) Terraform versions
- [ ] Documentation covers usage and migration from data sources
- [ ] Documentation covers write-only argument usage

---

## Open Questions

### 1. Naming Convention

Should ephemeral resources use the same name as data sources?

| Option | Example | Pros | Cons |
|--------|---------|------|------|
| Same name | `akeyless_dynamic_secret` | Intuitive, Terraform distinguishes by block type | Could confuse users |
| Different name | `akeyless_ephemeral_dynamic_secret` | Explicit | Verbose, redundant |

**Recommendation:** Same name — Terraform distinguishes by `ephemeral` vs `data` block.

### 2. Minimum Terraform Version

Should we require 1.10+ for the entire provider?

**Recommendation:** No — keep minimum version low. Ephemeral resources simply won't work on older Terraform (graceful error message).

### 3. Deprecation of Data Sources

Should we deprecate data sources that return secrets?

**Recommendation:** Not yet — some users may legitimately want state-stored secrets. Document both options and let users choose.

---

## Estimated Effort

| Phase | Scope | Description |
|-------|-------|-------------|
| Phase 1 | Ephemeral foundation | Mux setup + `akeyless_dynamic_secret` + `akeyless_static_secret` |
| Phase 2 | Write-Only P0 | `mysql_password_wo`, `bind_dn_password_wo`, `value_wo` |
| Phase 3 | Expand | Remaining ephemeral + write-only resources |

**Note:** Phases 1 and 2 can run in parallel.

---

## References

- [Terraform 1.11 Ephemeral Values Blog Post](https://www.hashicorp.com/en/blog/terraform-1-11-ephemeral-values-managed-resources-write-only-arguments)
- [Terraform Plugin Framework Documentation](https://developer.hashicorp.com/terraform/plugin/framework)
- [terraform-plugin-mux Documentation](https://developer.hashicorp.com/terraform/plugin/mux)
- [Ephemeral Resources RFC](https://github.com/hashicorp/terraform/blob/main/docs/plugin-protocol/ephemeral-resources.md)

---

## Appendix: Migration Guide for Users

### Before (data source — stored in state)

```hcl
data "akeyless_dynamic_secret" "db" {
  path = "/mysql-ds"
}

resource "aws_db_instance" "main" {
  password = data.akeyless_dynamic_secret.db.value
}
```

### After (ephemeral — not stored in state)

```hcl
ephemeral "akeyless_dynamic_secret" "db" {
  path = "/mysql-ds"
}

resource "aws_db_instance" "main" {
  password = ephemeral.akeyless_dynamic_secret.db.value
}
```

**Only change:** `data` → `ephemeral`

---

## Appendix: Write-Only Migration Guide for Users

### Before (password stored in state)

```hcl
resource "akeyless_dynamic_secret_mysql" "db" {
  name           = "/my-mysql-ds"
  mysql_username = "admin"
  mysql_password = "SuperSecret123!"  # Stored in state!
  mysql_host     = "db.example.com"
}
```

### After (password NOT stored in state)

```hcl
resource "akeyless_dynamic_secret_mysql" "db" {
  name                      = "/my-mysql-ds"
  mysql_username            = "admin"
  mysql_password_wo         = "SuperSecret123!"  # NOT stored
  mysql_password_wo_version = 1                  # Increment to trigger update
  mysql_host                = "db.example.com"
}
```

### Key Points for Users

1. **Both fields work** — `mysql_password` (old) and `mysql_password_wo` (new) both work
2. **Cannot use both** — They are mutually exclusive (`ConflictsWith`)
3. **Version is required** — When using `*_wo`, you must also set `*_wo_version`
4. **Increment to update** — To change the password, increment the version number

---

*Document version: 1.1 — Added Write-Only arguments scope*
