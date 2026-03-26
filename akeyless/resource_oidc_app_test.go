package akeyless

import (
	"context"
	"fmt"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestOidcAppResource(t *testing.T) {
	t.Parallel()

	appName := "test_oidc_app"
	appPath := testPath(appName)
	authMethodName := "test_oidc_app_auth"
	authMethodPath := testPath(authMethodName)

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "%v" {
			name = "%v"
		}

		resource "akeyless_oidc_app" "%v" {
			name 				= "%v"
			description 		= "Test OIDC app"
			redirect_uris 		= ["https://localhost/callback"]
			delete_protection 	= "true"
			tags 				= ["t1", "t2"]
			audience 			= "https://test-audience.example.com"
			accessibility 		= "regular"
			scopes 				= ["openid", "profile"]
			public 				= false
			permission_assignment = "[{\"assignment_type\":\"AUTH_METHOD\",\"access_id\":\"${akeyless_auth_method_api_key.%v.access_id}\",\"sub_claims\":{}}]"
		}
	`, authMethodName, authMethodPath, appName, appPath, authMethodName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "%v" {
			name = "%v"
		}

		resource "akeyless_oidc_app" "%v" {
			name 				= "%v"
			description 		= "Updated OIDC app"
			redirect_uris 		= ["https://localhost/callback", "https://localhost/callback2"]
			delete_protection 	= "false"
			tags 				= ["t1", "t3"]
			audience 			= "https://updated-audience.example.com"
			accessibility 		= "regular"
			scopes 				= ["openid", "email"]
			public 				= true
			permission_assignment = "[{\"assignment_type\":\"AUTH_METHOD\",\"access_id\":\"${akeyless_auth_method_api_key.%v.access_id}\",\"sub_claims\":{}}]"
		}
	`, authMethodName, authMethodPath, appName, appPath, authMethodName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy: func(s *terraform.State) error {
			// Check that both OIDC app and auth method are destroyed
			for _, rs := range s.RootModule().Resources {
				if rs.Type == "akeyless_oidc_app" || rs.Type == "akeyless_auth_method_api_key" {
					client := *testAccProvider.Meta().(*providerMeta).client
					token := *testAccProvider.Meta().(*providerMeta).token

					if rs.Type == "akeyless_oidc_app" {
						body := akeyless_api.DescribeItem{
							Name:  rs.Primary.ID,
							Token: &token,
						}
						_, res, err := client.DescribeItem(context.Background()).Body(body).Execute()
						if err == nil {
							return fmt.Errorf("OIDC App %s still exists", rs.Primary.ID)
						}
						if res != nil && res.StatusCode != 404 {
							return fmt.Errorf("OIDC App %s still exists with status %d", rs.Primary.ID, res.StatusCode)
						}
					} else if rs.Type == "akeyless_auth_method_api_key" {
						body := akeyless_api.AuthMethodGet{
							Name:  rs.Primary.ID,
							Token: &token,
						}
						_, res, err := client.AuthMethodGet(context.Background()).Body(body).Execute()
						if err == nil {
							return fmt.Errorf("Auth Method %s still exists", rs.Primary.ID)
						}
						if res != nil && res.StatusCode != 404 {
							return fmt.Errorf("Auth Method %s still exists with status %d", rs.Primary.ID, res.StatusCode)
						}
					}
				}
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkOidcAppExistsRemotely(appPath),
					resource.TestCheckResourceAttr("akeyless_oidc_app.test_oidc_app", "description", "Test OIDC app"),
					resource.TestCheckResourceAttr("akeyless_oidc_app.test_oidc_app", "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_oidc_app.test_oidc_app", "audience", "https://test-audience.example.com"),
					resource.TestCheckResourceAttr("akeyless_oidc_app.test_oidc_app", "accessibility", "regular"),
					resource.TestCheckResourceAttr("akeyless_oidc_app.test_oidc_app", "scopes.#", "2"),
					resource.TestCheckResourceAttr("akeyless_oidc_app.test_oidc_app", "public", "false"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkOidcAppExistsRemotely(appPath),
					resource.TestCheckResourceAttr("akeyless_oidc_app.test_oidc_app", "description", "Updated OIDC app"),
					resource.TestCheckResourceAttr("akeyless_oidc_app.test_oidc_app", "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_oidc_app.test_oidc_app", "audience", "https://updated-audience.example.com"),
					resource.TestCheckResourceAttr("akeyless_oidc_app.test_oidc_app", "scopes.#", "2"),
					resource.TestCheckResourceAttr("akeyless_oidc_app.test_oidc_app", "public", "true"),
				),
			},
			{
				ResourceName:            "akeyless_oidc_app.test_oidc_app",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"permission_assignment", "accessibility"},
			},
		},
	})
}

func checkOidcAppExistsRemotely(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		body := akeyless_api.DescribeItem{
			Name:  path,
			Token: &token,
		}

		_, _, err := client.DescribeItem(context.Background()).Body(body).Execute()
		if err != nil {
			return err
		}

		return nil
	}
}
