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

//  aws_iam_login {
//    access_id = ""
//  }

//  azure_ad_login {
//    access_id = ""
//  }

// jwt_login {
//    access_id = ""
//    // provide your JWT by storing it in an environment variable called JWT
// }

//  email_login {
//    admin_email = "user@mail.com"
//    admin_password = ""
//  }
}
