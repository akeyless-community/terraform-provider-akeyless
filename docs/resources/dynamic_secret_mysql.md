---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "akeyless_dynamic_secret_mysql Resource - terraform-provider-akeyless"
subcategory: ""
description: |-
  MySQL producer resource
---

# akeyless_dynamic_secret_mysql (Resource)

MySQL producer resource



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) Dynamic secret name

### Optional

- `db_server_certificates` (String) the set of root certificate authorities in base64 encoding that clients use when verifying server certificates
- `db_server_name` (String) Server name is used to verify the hostname on the returned certificates unless InsecureSkipVerify is given. It is also included in the client's handshake to support virtual hosting unless it is an IP address
- `encryption_key_name` (String) Encrypt dynamic secret details with following key
- `mysql_creation_statements` (String) MySQL Creation Statements
- `mysql_dbname` (String) MySQL DB name
- `mysql_host` (String) MySQL host name
- `mysql_password` (String, Sensitive) MySQL password
- `mysql_port` (String) MySQL port
- `mysql_revocation_statements` (String) MySQL Revocation Statements
- `mysql_username` (String) MySQL user
- `password_length` (String) The length of the password to be generated
- `secure_access_bastion_issuer` (String) Path to the SSH Certificate Issuer for your Akeyless Bastion
- `secure_access_db_name` (String) Enable Web Secure Remote Access
- `secure_access_enable` (String) Enable/Disable secure remote access, [true/false]
- `secure_access_host` (Set of String) Target DB servers for connections., For multiple values repeat this flag.
- `secure_access_web` (Boolean) Enable Web Secure Remote Access
- `ssl` (Boolean) Enable/Disable SSL [true/false]
- `ssl_certificate` (String) SSL CA certificate in base64 encoding generated from a trusted Certificate Authority (CA)
- `tags` (Set of String) List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2
- `target_name` (String) Name of existing target to use in producer creation
- `user_ttl` (String) User TTL

### Read-Only

- `id` (String) The ID of this resource.

