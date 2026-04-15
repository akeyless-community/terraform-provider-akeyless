---
name: resource-import-function
description: Pattern for Terraform resource import functions — dedicated per-file import func that delegates to Read. Use when adding an Importer to a resource, implementing terraform import support, or reviewing import functions.
---

# Resource Import Function Pattern

Each resource file must have its own dedicated import function that delegates to the resource's Read function.

## Structure

The import function:
- Lives in the same file as the resource
- Is placed **after** the Delete function
- Calls the resource's Read function directly

## Example

```go
func resourceGwSessionForwardingAwsS3Import(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	err := resourceGwSessionForwardingAwsS3Read(d, m)
	if err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
```

## Wiring

Reference the import function in the resource definition:

```go
Importer: &schema.ResourceImporter{
	State: resourceGwSessionForwardingAwsS3Import,
},
```

## Function order in file

1. Resource definition (`resourceFoo()`)
2. Create (in most files, not all)
2. Read
3. Update (if has no Create, then Create = Update)
4. Delete
5. **Import** (last)

## Do not

- Use a shared/generic import wrapper across files
- Use `schema.ImportStatePassthroughContext` (Read functions are non-Context)
- Inline the import logic into the resource definition
