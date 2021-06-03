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

//    access_id = ""
//    access_key = ""
  }
}

resource "akeyless_auth_method" "api_key" {
  path = "terraform-tests/auth-method-api-key-demo"
  api_key {
  }

//  saml {
//    idp_metadata_url = ""
//    unique_identifier = ""
//  }

//  aws_iam {
//    bound_aws_account_id = ""
//    bound_arn = ""
//  }

//  azure_ad {
//    bound_tenant_id = ""
//    jwks_uri = ""
//    custom_audience = ""
//    custom_issuer = ""
//  }

//  gcp {
//    service_account_creds_data = ""
//    iam {
//      bound_service_accounts = ["110114356712893329431"]
//    }
//  }

}

resource "akeyless_role" "role" {
  depends_on = [
    akeyless_auth_method.api_key
  ]
  name = "terraform-tests/demo-role"

  assoc_auth_method {
    am_name = akeyless_auth_method.api_key.id
    sub_claims = {
      "groups" = "developers,readers"
      "users" = "bob"
    }
  }

  rules {
    capability = ["read","list"]
    path = "/terraform-tests/*"
    rule_type = "auth-method-rule"
  }
}

resource "akeyless_static_secret" "secret" {
  path = "terraform-tests/secret"
  value = "this value was set from terraform"
}

data "akeyless_secret" "secret" {
  depends_on = [
    akeyless_static_secret.secret
  ]
  path = "terraform-tests/secret"
}

output "secret" {
  value = data.akeyless_secret.secret
}

output "auth_method" {
  value = akeyless_auth_method.api_key
}
