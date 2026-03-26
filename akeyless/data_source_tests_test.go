// generated file
package akeyless

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAuthMethodDataSource(t *testing.T) {
	t.Parallel()
	name := "test_ds_auth_method"
	path := testPath(name)
	deleteAuthMethod(path, "api_key")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "%v" {
			name = "%v"
		}

		data "akeyless_auth_method" "%v" {
			path       = "%v"
			depends_on = [akeyless_auth_method_api_key.%v]
		}
	`, name, path, name, path, name)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(fmt.Sprintf("data.akeyless_auth_method.%v", name), "access_id"),
					resource.TestCheckResourceAttrSet(fmt.Sprintf("data.akeyless_auth_method.%v", name), "auth_method_name"),
				),
			},
		},
	})
}

func TestRoleDataSource(t *testing.T) {
	t.Parallel()
	roleName := "test_ds_role"
	rolePath := testPath(roleName)
	deleteRole(rolePath)
	defer deleteRole(rolePath)

	config := fmt.Sprintf(`
		resource "akeyless_role" "%v" {
			name        = "%v"
			description = "test role for data source"
		}

		data "akeyless_role" "%v" {
			name       = "%v"
			depends_on = [akeyless_role.%v]
		}
	`, roleName, rolePath, roleName, rolePath, roleName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(fmt.Sprintf("data.akeyless_role.%v", roleName), "role_name"),
					resource.TestCheckResourceAttrSet(fmt.Sprintf("data.akeyless_role.%v", roleName), "assoc_auth_method_with_rules"),
				),
			},
		},
	})
}

func TestTagsDataSource(t *testing.T) {
	t.Parallel()
	secretName := "test_ds_tags"
	secretPath := testPath(secretName)

	config := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path  = "%v"
			value = "test-value"
			tags  = ["tag1", "tag2"]
		}

		data "akeyless_tags" "%v" {
			name       = "%v"
			depends_on = [akeyless_static_secret.%v]
		}
	`, secretName, secretPath, secretName, secretPath, secretName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(fmt.Sprintf("data.akeyless_tags.%v", secretName), "tags.#"),
				),
			},
		},
	})
}

func TestTargetDataSource(t *testing.T) {
	t.Parallel()
	targetName := "test_ds_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_web" "%v" {
			name        = "%v"
			url         = "https://example.com"
			description = "test target for data source"
		}

		data "akeyless_target" "%v" {
			name       = "%v"
			depends_on = [akeyless_target_web.%v]
		}
	`, targetName, targetPath, targetName, targetPath, targetName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(fmt.Sprintf("data.akeyless_target.%v", targetName), "target_name"),
					resource.TestCheckResourceAttrSet(fmt.Sprintf("data.akeyless_target.%v", targetName), "target_type"),
					resource.TestCheckResourceAttr(fmt.Sprintf("data.akeyless_target.%v", targetName), "description", "test target for data source"),
				),
			},
		},
	})
}
