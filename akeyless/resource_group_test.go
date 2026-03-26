package akeyless

import (
	"context"
	"fmt"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestGroupResource(t *testing.T) {
	t.Parallel()

	groupName := "test_group"
	groupPath := testPath(groupName)
	authMethodName := "test_group_auth"
	authMethodPath := testPath(authMethodName)

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "%v" {
			name = "%v"
		}

		resource "akeyless_group" "%v" {
			name 				= "%v"
			group_alias 		= "testalias"
			description 		= "Test group description"
			user_assignment 	= "[{\"access_id\":\"${akeyless_auth_method_api_key.%v.access_id}\",\"sub_claims\":{}}]"
		}
	`, authMethodName, authMethodPath, groupName, groupPath, authMethodName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "%v" {
			name = "%v"
		}

		resource "akeyless_group" "%v" {
			name 				= "%v"
			group_alias 		= "testaliasupd"
			description 		= "Updated test group description"
			user_assignment 	= "[{\"access_id\":\"${akeyless_auth_method_api_key.%v.access_id}\",\"sub_claims\":{}}]"
		}
	`, authMethodName, authMethodPath, groupName, groupPath, authMethodName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy: func(s *terraform.State) error {
			// Check that both group and auth method are destroyed
			for _, rs := range s.RootModule().Resources {
				if rs.Type == "akeyless_group" || rs.Type == "akeyless_auth_method_api_key" {
					client := *testAccProvider.Meta().(*providerMeta).client
					token := *testAccProvider.Meta().(*providerMeta).token

					if rs.Type == "akeyless_group" {
						body := akeyless_api.GetGroup{
							Name:  rs.Primary.ID,
							Token: &token,
						}
						_, res, err := client.GetGroup(context.Background()).Body(body).Execute()
						if err == nil {
							return fmt.Errorf("Group %s still exists", rs.Primary.ID)
						}
						if res != nil && res.StatusCode != 404 {
							return fmt.Errorf("Group %s still exists with status %d", rs.Primary.ID, res.StatusCode)
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
					checkGroupExistsRemotely(groupPath),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkGroupExistsRemotely(groupPath),
				),
			},
		},
	})
}

func checkGroupExistsRemotely(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		body := akeyless_api.GetGroup{
			Name:  path,
			Token: &token,
		}

		_, _, err := client.GetGroup(context.Background()).Body(body).Execute()
		if err != nil {
			return err
		}

		return nil
	}
}
