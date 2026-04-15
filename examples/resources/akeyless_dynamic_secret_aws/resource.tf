terraform {
  required_providers {
    akeyless = {
      version = ">= 1.0.0"
      source  = "akeyless-community/akeyless"
    }
  }
}

provider "akeyless" {
  api_key_login {
    access_id  = ""
    access_key = ""
  }
}

resource "akeyless_dynamic_secret_aws" "example" {
  name                = "/my-aws-secret"
  target_name         = "/my-aws-target"
  access_mode         = "assume_role"
  aws_role_arns       = "arn:aws:iam::123456789012:role/MyRole"
  user_ttl            = "60m"
  session_tags        = "Key=Team,Value=Platform Key=Environment,Value=Dev"
  transitive_tag_keys = "Team"
}
