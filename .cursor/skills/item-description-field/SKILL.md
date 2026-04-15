---
name: item-description-field
description: Correct field to use for item descriptions in Read functions — ItemMetadata for DescribeItem, Description for specific Get endpoints. Use when implementing or reviewing d.Set("description", ...) in resource read functions.
---

# Item Description Field Pattern

When reading item descriptions in resource Read functions, use the correct field based on the API call.

## DescribeItem API

Use `ItemMetadata`:

```go
if rOut.ItemMetadata != nil {
    err = d.Set("description", *rOut.ItemMetadata)
    if err != nil {
        return err
    }
}
```

**Do not use** `ItemGeneralInfo.DisplayMetadata`.

## Specific Get Endpoints

Use the direct `Description` field from the response structure.
