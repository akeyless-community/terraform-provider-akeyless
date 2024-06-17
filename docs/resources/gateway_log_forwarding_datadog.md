---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "akeyless_gateway_log_forwarding_datadog Resource - terraform-provider-akeyless"
subcategory: ""
description: |-
  Log Forwarding config for datadog
---

# akeyless_gateway_log_forwarding_datadog (Resource)

Log Forwarding config for datadog



<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `api_key` (String, Sensitive) Datadog api key
- `enable` (String) Enable Log Forwarding [true/false]
- `host` (String) Datadog host
- `log_service` (String) Datadog log service
- `log_source` (String) Datadog log source
- `log_tags` (String) A comma-separated list of Datadog log tags formatted as key:value strings
- `output_format` (String) Logs format [text/json]
- `pull_interval` (String) Pull interval in seconds

### Read-Only

- `id` (String) The ID of this resource.

