---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "akeyless_associate_role_auth_method Resource - terraform-provider-akeyless"
subcategory: ""
description: |-
  Association between role and auth method
---

# akeyless_associate_role_auth_method (Resource)

Association between role and auth method



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **am_name** (String) The auth method to associate
- **role_name** (String) The role to associate

### Optional

- **case_sensitive** (String) Treat sub claims as case-sensitive
- **id** (String) The ID of this resource.
- **sub_claims** (Map of String) key/val of sub claims, e.g group=admins,developers

