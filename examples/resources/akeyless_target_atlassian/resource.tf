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

# Atlassian Cloud: a user API token is paired with the account email.
resource "akeyless_target_atlassian" "cloud" {
  name            = "terraform/atlassian-cloud"
  atlassian_url   = "https://<site>.atlassian.net"
  atlassian_email = "<account-email>"
  atlassian_token = var.atlassian_api_token
  description     = "Atlassian Cloud site scanned by Identity & Secrets Intelligence"
}

# Jira Data Center: a personal access token, no email.
resource "akeyless_target_atlassian" "data_center" {
  name            = "terraform/atlassian-dc"
  atlassian_url   = "https://jira.<company>.example/jira"
  atlassian_token = var.atlassian_pat
}
