---
name: update-existing-command
description: Guides updating an existing Terraform resource or data source with new fields or functionality — schema changes, CRUD updates, backward compatibility, and docs regeneration. Use when adding fields to an existing resource_*.go or data_source_*.go file.
---

# Updating an Existing Command/Resource

## 1. Update the Akeyless SDK

1.  Run `go get -u github.com/akeylesslabs/akeyless-go/v5`
2.  Run `go mod tidy`

## 2. Update the Resource/Data Source Implementation

1.  Identify the relevant file in the `akeyless/` directory (e.g., `resource_<name>.go`).
2.  **Schema Update**: Add or update fields in the `Schema` map.
    *   Use `Type`, `Optional`, `Description`, etc.
    *   If the field is sensitive, set `Sensitive: true`.
3.  **CRUD Operations**: Update the `resource<Name>Create`, `resource<Name>Read`, `resource<Name>Update` functions.
    *   Map the new schema fields to the SDK struct fields.
    *   Ensure the API call includes the new parameters.

Ignore resources that have a `DeprecationMessage` set.
These rules also apply when creating new resources — always ensure sensitive fields are marked, defaults match types, and read functions cover all writable params that the API returns.
If the API (SDK struct) does not expose a field in its response, it cannot be read back — do not add a `d.Set()` for it.

### Key lessons
- Never remove existing schema fields from a resource — it breaks backward compatibility for existing users
- When adding a field to Create, also add it to Update and Read (if the API supports it)
- Check the SDK response struct to confirm which fields are actually returned before writing `d.Set()` calls
- Use the newer type-specific APIs when available (e.g. `AuthMethodGet` over `GetAuthMethod`, `GatewayCreateMigrationAWS` over `GatewayCreateMigration`)

## 3. Update Documentation

Documentation is auto-generated from the code comments and schema descriptions.

1.  **Schema Descriptions**: Ensure the `Description` fields in your Go schema definitions are accurate and updated.
2.  **Generate Docs**: Run the following command to regenerate the documentation files:
    ```bash
    go generate
    ```
3.  **Review**: Check the changes in the `docs/` folder to ensure the generated documentation looks correct.

## 4. Format and Validate

1.  Run `gofmt -w .` to format the code.
2.  Run `go mod tidy` again if needed.
