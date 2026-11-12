---
name: code-review
description: Review Terraform provider diffs for SDK-delta completeness, Terraform lifecycle correctness, refresh/import state, tests, documentation, and repository conventions.
---

# Terraform Provider Code Review

Review the actual diff and its base branch. Report only findings supported by code, API behavior, or test evidence.

Do not edit code, commit, push, or post PR comments unless the user explicitly asks.

## Review scope

1. Identify the changed provider resources, data sources, tests, documentation, and registration.
2. For SDK-sync work, compare the SDK delta with the provider diff.
3. An SDK field does not prove public support. Confirm that the Gateway/CLI/API accepts and returns the field before exposing it in Terraform.
4. Review the full resource lifecycle, not only the Create request.

## Code style

Before adding or reviewing fields, inspect the closest existing resource and follow its established shape:

- Keep schema placement, naming, request construction, API-response mapping, and error handling consistent with nearby code.
- Reuse existing types and helpers. Do not add a new abstraction only for one field.
- Group related fields in a helper only when the helper owns the complete logical group. Do not move only some related fields into a special helper without a clear reason.
- Preserve existing conditional behavior. If surrounding fields are set only when the API returns their map keys, new fields should do the same.
- Prefer simple explicit field mappings when that is the pattern in the resource. Do not introduce templates, reflection, or generic maps only to reduce repeated lines.

## Field lifecycle checklist

For each new or changed field, review:

- **Schema:** type, default, sensitivity, `Computed`, `ForceNew`, conflicts, path normalization, and description.
- **Create and Update:** send the value only when the public API supports it and the Terraform configuration requires it.
- **Read:** set each writable value returned by the API. Check all `d.Set` errors.
- **Import:** reuse the resource Read function when it creates the same Terraform state.
- **Delete:** check whether replacement or deletion can cause unexpected external effects.
- **Tests and docs:** cover the behavior users receive and describe it accurately.

Never remove an existing schema field without explicit backward-compatibility approval.

## State and update rules

- Preserve the API difference between an absent map key and an explicit empty value:

  ```go
  value, ok := attributes["field_name"]
  if ok {
      // Set the Terraform field.
  }
  ```

- Do not send Terraform zero values (`""`, `false`, empty list) unless the user configured or changed that field. A zero value can unintentionally clear remote settings.
- A no-op Update handler is wrong when the changed Terraform field must change remote state.
- Use `ForceNew` only after checking the whole replacement flow: delete, create, possible external writes, and temporary loss of association.
- If update or replacement is unsafe or unsupported, make that Terraform behavior explicit and test it.
- Mark passwords, keys, tokens, and credentials `Sensitive: true`. Use `WriteOnly` only when Terraform must not retain the value.

## Test rules

- Prefer explicit, readable HCL over templates that hide resource behavior.
- Test create, refresh/read, a meaningful update when supported, import when applicable, and cleanup.
- A final `PlanOnly` step is valid only when an earlier step already applied the change and the plan proves there is no drift.
- Add behavior to an existing resource test when it covers the same flow. Do not create an isolated test only for one field without a reason.
- Put new resource and data source tests under `akeyless/tests/`, in the established test package for the required Gateway dependency. Do not add standalone `*_test.go` files beside provider source files.
- A skipped integration test needs: a clear external dependency, evidence it passed at least once, and a tracked condition for re-enabling it.

## Validation

Use checks that do not modify the working tree unless the user asked for formatting:

```bash
gofmt -d <touched-go-files>
go test ./... -run '^$'
git diff --check
```

Run focused acceptance tests when the local Gateway and credentials are available. State clearly when a test was skipped rather than passed.

## Report format

```markdown
## Review: <scope>

### Blocking
- `<file>:<line>` — <problem and user impact>
  - Evidence: <code path or test result>
  - Fix: <specific correction>

### Major
...

### Passed checks
- <commands and results>

### Open questions
- <only decisions that need product or API-owner input>
```

If there are no findings, say so and list the validation performed.
