package akeyless

import (
	"context"
	"fmt"
	"testing"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestBCDescription(t *testing.T) {
	t.Run("secret", func(t *testing.T) {
		t.Run("metadata", func(t *testing.T) {
			testBCSecretResource(t, "metadata")
		})

		t.Run("description", func(t *testing.T) {
			testBCSecretResource(t, "description")
		})
	})

	t.Run("key", func(t *testing.T) {
		t.Run("metadata", func(t *testing.T) {
			testBCKeyResource(t, "metadata")
		})

		t.Run("description", func(t *testing.T) {
			testBCKeyResource(t, "description")
		})
	})

	t.Run("target", func(t *testing.T) {
		t.Run("comment", func(t *testing.T) {
			testBCTargetResource(t, "comment")
		})

		t.Run("description", func(t *testing.T) {
			testBCTargetResource(t, "description")
		})
	})

	t.Run("role", func(t *testing.T) {
		t.Run("comment", func(t *testing.T) {
			testBCRoleResource(t, "comment")
		})

		t.Run("description", func(t *testing.T) {
			testBCRoleResource(t, "description")
		})
	})

}

func testBCSecretResource(t *testing.T, field string) {
	t.Parallel()

	secretName := "test_bc_secret_" + field
	secretPath := testPath(secretName)
	defer deleteItem(t, secretPath)

	config := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path 	= "%v"
			value	= "1234"
			%s 		= "aaa"
		}
	`, secretName, secretPath, field)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path 	= "%v"
			value 	= "1234"
			%s 		= ""
		}
	`, secretName, secretPath, field)

	tesItemResource(t, config, configUpdate, secretPath)
}

func testBCKeyResource(t *testing.T, field string) {
	t.Parallel()

	secretName := "test_bc_key_" + field
	secretPath := testPath(secretName)
	defer deleteItem(t, secretPath)

	config := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 	= "%v"
			alg 	= "RSA1024"
			%s 		= "aaa"
		}
	`, secretName, secretPath, field)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 	= "%v"
			alg 	= "RSA1024"
			%s 		= ""
		}
	`, secretName, secretPath, field)

	tesItemResource(t, config, configUpdate, secretPath)
}

func testBCTargetResource(t *testing.T, field string) {
	t.Parallel()

	targetName := "test_bc_target_" + field
	targetPath := testPath(targetName)
	defer deleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 		= "%v"
			db_type   	= "mysql"
			user_name 	= "user1"
			pwd 		= "1234"
			host 		= "127.0.0.1"
			port 		= "3306"
			db_name 	= "mysql"
			%s 			= "aaa"
		}
	`, targetName, targetPath, field)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 		= "%v"
			db_type   	= "mysql"
			user_name 	= "user1"
			pwd 		= "1234"
			host 		= "127.0.0.1"
			port 		= "3306"
			db_name 	= "mysql"
			%s 			= ""
		}
	`, targetName, targetPath, field)

	tesTargetResource(t, config, configUpdate, targetPath)
}

func testBCRoleResource(t *testing.T, field string) {
	t.Parallel()

	roleName := "test_bc_role_" + field
	rolePath := testPath(roleName)
	defer deleteRole(rolePath)

	config := fmt.Sprintf(`
		resource "akeyless_role" "%v" {
			name	= "%v"
			%s 		= "aaa"
		}
	`, roleName, rolePath, field)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_role" "%v" {
			name	= "%v"
			%s 		= ""
		}
	`, roleName, rolePath, field)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkRemoveRoleRemotelyProd(rolePath),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkRemoveRoleRemotelyProd(rolePath),
				),
			},
		},
	})
}

func checkRemoveRoleRemotelyProd(roleName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GetRole{
			Name:  roleName,
			Token: &token,
		}

		_, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}

		return nil
	}
}
