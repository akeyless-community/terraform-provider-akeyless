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
  path = "auth-method-api-key"
  api_key {
  }
}


resource "akeyless_auth_method" "aws_iam" {
  path = "auth-method-aws-iam"
  aws_iam {
    bound_aws_account_id = ["516111111111"]
  }
}

data "akeyless_auth_method" "api_key" {
  path = "auth-method-api-key"
}

output "api_key" {
  value = data.akeyless_auth_method.api_key
}