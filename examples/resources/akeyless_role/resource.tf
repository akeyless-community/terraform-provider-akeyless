terraform {
  required_providers {
    akeyless = {
      version = ">= 1.0.0"
      source = "akeyless-community/akeyless"
    }
  }
}


provider "akeyless" {
  api_key_login {
    access_id = ""
    access_key = ""
  }
}


resource "akeyless_auth_method" "api_key" {
  path = "auth-method-api-key-demo"
  api_key {
  }
}

resource "akeyless_role" "role" {
  depends_on = [
    akeyless_auth_method.api_key
  ]
  name = "demo-role"

  assoc_auth_method {
    am_name = "auth-method-api-key-demo"
    sub_claims = {
      "groups" = "developers,readers"
      "users" = "bob"
    }
  }
  rules {
    capability = ["read"]
    path = "/*"
    rule_type = "auth-method-rule"
  }
}

data "akeyless_role" "demo-role" {
  name = akeyless_role.role.id
}

output "demo-role" {
  value = data.akeyless_role.demo-role
}