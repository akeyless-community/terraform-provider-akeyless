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

resource "akeyless_static_secret" "secret" {
  path = "terraform/secret"
  value = "this value was set from terraform"
}