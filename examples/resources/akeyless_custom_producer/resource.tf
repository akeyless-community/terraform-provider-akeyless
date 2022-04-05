terraform {
  required_providers {
    akeyless = {
      version = ">= 1.1.2"
      source = "akeyless-community/akeyless"
    }
  }
}


provider "akeyless" {
  # The gateway-create-producer-custom endpoint is not available in aKeyless public gateway: https://api.akeyless.io
  # We have to configure our gateway:
  api_gateway_address = "https://akeyless.example.com:8080/v2"
  api_key_login {
    access_id = ""
    access_key = ""
  }
}

resource "akeyless_producer_custom" "my_custom_producer" {
  name = "my_custom_producer"
  create_sync_url = "https://webhook.example.com/sync/create"
  revoke_sync_url = "https://webhook.example.com/sync/revoke"
  rotate_sync_url = "https://webhook.example.com/sync/rotate"
  payload = "secret data stored by Akeyless"
  timeout_sec = "60"
  user_ttl = "5m"
  tags = ["tag1", "tag2"]
}