---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "akeyless_dynamic_secret_gitlab Resource - terraform-provider-akeyless"
subcategory: ""
description: |-
  Gitlab dynamic secret resource.
---

# akeyless_dynamic_secret_gitlab (Resource)

Gitlab dynamic secret resource.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) Dynamic secret name

### Optional

- `delete_protection` (String) Protection from accidental deletion of this item, [true/false]
- `description` (String) Description of the object
- `gitlab_access_token` (String, Sensitive) Gitlab access token
- `gitlab_access_type` (String) Gitlab access token type [project,group]
- `gitlab_certificate` (String, Sensitive) Gitlab tls certificate (base64 encoded)
- `gitlab_role` (String) Gitlab role
- `gitlab_token_scopes` (String) Comma-separated list of access token scopes to grant
- `gitlab_url` (String) Gitlab base url
- `group_name` (String) Gitlab group name, required for access-type=group
- `installation_organization` (String) Gitlab project name, required for access-type=project
- `tags` (Set of String) A comma-separated list of tags attached to this secret
- `target_name` (String) Name of an existing target
- `ttl` (String) Access Token TTL

### Read-Only

- `id` (String) The ID of this resource.


