package akeyless

import (
	"context"
	"fmt"
	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"testing"
)

func TestStaticResource(t *testing.T) {
	secretName := "test_secret"
	secretPath := testPath("path_secret")
	config := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path = "%v"
			value = "secretpassword"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path = "%v"
			value = "update-secret"
			secure_access_enable = "false"
			secure_access_url    = "http://google.com"
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
