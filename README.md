# Akeyless Terraform Provider
<p align="middle">
    <br/>
<a href="https://www.akeyless.io/">
    <img src="https://akeylesscli.s3.us-east-2.amazonaws.com/images/akeyless_dark_logo.png" alt="Akeyless logo" title="Akeyless" width="250"/>
</a>
</p>

> [Akeyless][akeyless] Protect and automate access to credentials, keys, tokens, and API-Keys across your DevOps tools and Cloud platforms using a secured vault.

## Usage Example

### Terraform v0.13
```hcl
terraform {
  required_providers {
    akeyless = {
      version = ">= 1.0.0"
      source  = "akeyless-community/akeyless"
    }
  }
}

provider "akeyless" {
  api_gateway_address = "https://api.akeyless.io"

  api_key_login {
    access_id = ""
    access_key = ""
  }
}

resource "akeyless_static_secret" "secret" {
  path = "terraform/secret"
  value = "this value was set from terraform"
}

data "akeyless_secret" "secret" {
  path = "terraform/secret"
}

output "secret" {
  value = data.akeyless_secret.secret
}
```

## Develop

### Requirements
- [Terraform](https://www.terraform.io/downloads.html) >=1.0.0
- [Go](https://golang.org/doc/install) >=1.15

### Building
Clone the repository :
```
git clone https://github.com/akeylesslabs/terraform-provider-akeyless.git
```
Build:
```
make build-linux
```

Execute Terraform from local provider source:
```
make install-linux
```

```hcl
terraform {
  required_providers {
    akeyless = {
      version = "1.0.0-dev"
      source  = "akeyless-community/akeyless"
    }
  }
}  
```


## Testing
To run the [acceptance tests](https://www.terraform.io/docs/extend/testing/acceptance-tests/index.html), the following environment variables need to be set up.

* `AKEYLESS_ACCESS_ID` - Access ID (API-Key with admin permissions).
* `AKEYLESS_ACCESS_KEY` - Access key.

Only for the GCP acceptance tests:
* `TF_ACC_GCP_SERVICE_ACCOUNT` - Service Account creds data, base64 encoded.
* `TF_ACC_GCP_BOUND_SERVICE_ACC` - A list of Service Accounts.

Run `make testacc`



[akeyless]: https://akeyless.io
