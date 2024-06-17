---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "akeyless_gateway_cache Resource - terraform-provider-akeyless"
subcategory: ""
description: |-
  Cache settings
---

# akeyless_gateway_cache (Resource)

Cache settings



<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `backup_interval` (String) Secure backup interval in minutes. To ensure service continuity in case of power cycle and network outage secrets will be backed up periodically per backup interval
- `enable_cache` (String) Enable cache [true/false]
- `enable_proactive` (String) Enable proactive caching [true/false]
- `minimum_fetch_interval` (String) When using Cache or/and Proactive Cache, additional secrets will be fetched upon requesting a secret, based on the requestor's access policy. Define minimum fetching interval to avoid over fetching in a given time frame
- `stale_timeout` (String) Stale timeout in minutes, cache entries which are not accessed within timeout will be removed from cache

### Read-Only

- `id` (String) The ID of this resource.

