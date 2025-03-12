package akeyless

import (
	"context"
	"fmt"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestStaticResource(t *testing.T) {

	t.Parallel()

	secretName := "test_secret"
	secretPath := testPath(secretName)

	config := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path 				= "%v"
			value 				= "{\"secret value\":\"abc\"}"
			format 				= "json"
			tags 				= ["t1", "t2"]
			description 		= "aaaa"
            keep_prev_version	= "true"
			delete_protection  = "true"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path 						= "%v"
			value 						= "value2"
			secure_access_enable 		= "false"
			secure_access_web_browsing 	= "true"
			secure_access_url 			= "http://abc.com"
			tags 						= ["t1", "t3"]
			description 				= "bbbb"
			delete_protection  = "true"
		}
	`, secretName, secretPath)

	runStaticSecretTest(t, config, secretPath, configUpdate)
}

func TestStaticPasswordResource(t *testing.T) {

	t.Parallel()

	secretName := "test_password2"
	secretPath := testPath(secretName)

	config := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path 				= "%v"
			type 				= "password"
			username 			= "user"
			password 			= "abc"
			inject_url 			= ["http://abc.com"]
			custom_field		= {
				"groups"  = "admins1",
				"users"   = "user1",
			}
			tags 				= ["t1", "t2"]
			description 		= "my password"
            keep_prev_version	= "true"
			delete_protection  = "true"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path 				= "%v"
			type 				= "password"
			username 			= "user2"
			password 			= "def"
			inject_url 			= ["http://abc.com", "http://def.com"]
			custom_field		= {
				"groups"  = "admins2",
			}
			tags 				= ["t5"]
			description 		= "my updated password"
            keep_prev_version	= "false"
			delete_protection  = "true"
		}
	`, secretName, secretPath)

	runStaticSecretTest(t, config, secretPath, configUpdate)
}

func runStaticSecretTest(t *testing.T, config string, secretPath string, configUpdate string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkSecretExistsRemotely(secretPath),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkSecretExistsRemotely(secretPath),
				),
			},
		},
	})
}

func checkSecretExistsRemotely(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		gsvBody := akeyless_api.GetSecretValue{
			Names: []string{path},
			Token: &token,
		}

		_, _, err := client.GetSecretValue(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}

		return nil
	}
}
