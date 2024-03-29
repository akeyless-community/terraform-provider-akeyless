---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "akeyless_producer_artifactory Resource - terraform-provider-akeyless"
subcategory: ""
description: |-
  Artifactory producer resource
---

# akeyless_producer_artifactory (Resource)

Artifactory producer resource



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `artifactory_token_audience` (String) A space-separate list of the other Artifactory instances or services that should accept this token., for example: jfrt@*
- `artifactory_token_scope` (String) Token scope provided as a space-separated list, for example: member-of-groups:readers
- `name` (String) Producer name

### Optional

- `artifactory_admin_name` (String) Admin name
- `artifactory_admin_pwd` (String) Admin API Key/Password
- `base_url` (String) Artifactory REST URL, must end with artifactory postfix
- `producer_encryption_key_name` (String) Encrypt producer with following key
- `tags` (Set of String) List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2
- `target_name` (String) Name of existing target to use in producer creation
- `user_ttl` (String) User TTL

### Read-Only

- `id` (String) The ID of this resource.


