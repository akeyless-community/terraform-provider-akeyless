---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "akeyless_target_artifactory Resource - terraform-provider-akeyless"
subcategory: ""
description: |-
  Artifactory Target resource
---

# akeyless_target_artifactory (Resource)

Artifactory Target resource



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `artifactory_admin_name` (String) Admin name
- `artifactory_admin_pwd` (String) Admin API Key/Password
- `base_url` (String) Artifactory REST URL, must end with artifactory postfix
- `name` (String) Target name

### Optional

- `description` (String) Description of the object
- `key` (String) The name of a key that used to encrypt the target secret value (if empty, the account default protectionKey key will be used)

### Read-Only

- `id` (String) The ID of this resource.


