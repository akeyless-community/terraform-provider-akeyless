package akeyless

import (
	"context"
	"fmt"
	"testing"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestStaticResource(t *testing.T) {

	t.Parallel()

	secretName := "test_secret"
	secretPath := testPath(secretName)

	config := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path 		= "%v"
			value 		= "value1"
			tags 		= ["t1", "t2"]
			description = "aaaa"
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
		}
	`, secretName, secretPath)

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
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GetSecretValue{
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
