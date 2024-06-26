---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "akeyless_gateway_log_forwarding_elasticsearch Resource - terraform-provider-akeyless"
subcategory: ""
description: |-
  Log Forwarding config for elasticsearch
---

# akeyless_gateway_log_forwarding_elasticsearch (Resource)

Log Forwarding config for elasticsearch



<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `api_key` (String, Sensitive) Elasticsearch api key relevant only for api_key auth-type
- `auth_type` (String) Elasticsearch auth type [api_key/password]
- `cloud_id` (String) Elasticsearch cloud id relevant only for cloud server-type
- `enable` (String) Enable Log Forwarding [true/false]
- `enable_tls` (Boolean) Enable tls
- `index` (String) Elasticsearch index
- `nodes` (String) Elasticsearch nodes relevant only for nodes server-type
- `output_format` (String) Logs format [text/json]
- `password` (String, Sensitive) Elasticsearch password relevant only for password auth-type
- `pull_interval` (String) Pull interval in seconds
- `server_type` (String) Elasticsearch server type [nodes/cloud]
- `tls_certificate` (String, Sensitive) Elasticsearch tls certificate (PEM format) in a Base64 format
- `user_name` (String) Elasticsearch user name relevant only for password auth-type

### Read-Only

- `id` (String) The ID of this resource.


