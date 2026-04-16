---
name: test-fixture-setup
description: Create test fixture dependencies (keys, issuers, targets, secrets) via SDK API calls in test setup, not via Terraform depends_on. Use when writing or reviewing acceptance tests that need pre-existing items, or when a test fails because a Terraform resource references an item that doesn't exist.
---

# Test Fixture Setup

## Rule

When an acceptance test resource depends on a pre-existing item (e.g. a gateway config resource that references an SSH cert issuer), create that item **via the SDK API** in the test function body, not as a Terraform resource with `depends_on`.

**Why:** Terraform resources inside test configs can fail with ordering issues, and mixing infrastructure setup with the resource under test makes failures harder to diagnose. API-created fixtures are deterministic and independent of the Terraform run.

## Pattern

```go
func TestMyResource(t *testing.T) {
    testutils.SkipIfNoGateway(t)

    // 1. Create fixtures via API
    keyPath := testPath("my_key")
    testutils.CreateDfcKey(t, keyPath)
    t.Cleanup(func() {
		testutils.DeleteItem(t, keyPath)
	})

    issuerPath := testPath("my_issuer")
    testutils.CreateSshCertIssuer(t, keyPath, issuerPath, "test")
    t.Cleanup(func() {
		testutils.DeleteItem(t, issuerPath)
	})

    // 2. Reference fixtures by path in Terraform config
    config := fmt.Sprintf(`
        resource "akeyless_my_resource" "%v" {
            some_item_ref = "%v"
            other_field   = "value1"
        }
    `, name, issuerPath)

    configUpdate := fmt.Sprintf(`
        resource "akeyless_my_resource" "%v" {
            some_item_ref = "%v"
            other_field   = "value2"
        }
    `, name, issuerPath)

    testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
}
```

## Available Helpers

All in `akeyless/tests/testutils/testutils.go`:

| Helper | Creates | Requires |
|--------|---------|----------|
| `CreateDfcKey(t, name)` | DFC key (RSA1024) | — |
| `CreateProtectionKey(t, name)` | AES128-GCM key | — |
| `CreateSshCertIssuer(t, keyName, issuerName, users)` | SSH cert issuer | DFC key |
| `CreatePkiCertIssuer(t, keyName, issuerName, destPath, cn, uriSan)` | PKI cert issuer | DFC key |
| `CreateCertificate(t, certName, certB64, keyB64)` | Certificate item | Generated cert/key pair |
| `CreateSecret(t, *TestSecret)` | Static secret | — |
| `DeleteItem(t, path)` | — | Always `defer` after create |
| `DeleteItemIfExists(t, path)` | — | Silent if missing |

## Cleanup

Always `defer testutils.DeleteItem(t, path)` immediately after each create call, before the next create. This ensures cleanup runs in reverse order even if a later create fails.
