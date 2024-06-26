---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "akeyless_dynamic_secret_custom Resource - terraform-provider-akeyless"
subcategory: ""
description: |-
  Custom dynamic secret resource
---

# akeyless_dynamic_secret_custom (Resource)

Custom dynamic secret resource



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `create_sync_url` (String) URL of an endpoint that implements /sync/create method
- `name` (String) Dynamic secret name
- `revoke_sync_url` (String) URL of an endpoint that implements /sync/revoke method

### Optional

- `admin_rotation_interval_days` (Number) Rotation period in days
- `enable_admin_rotation` (Boolean) Enable automatic admin credentials rotation
- `encryption_key_name` (String) Encrypt dynamic secret details with following key
- `payload` (String) Secret payload to be sent with each create/revoke webhook request
- `rotate_sync_url` (String) URL of an endpoint that implements /sync/rotate method
- `tags` (Set of String) List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2
- `timeout_sec` (Number) Maximum allowed time in seconds for the webhook to return the results
- `user_ttl` (String) User TTL

### Read-Only

- `id` (String) The ID of this resource.


