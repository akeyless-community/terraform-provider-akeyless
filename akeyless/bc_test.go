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

		t.Run("both", testBCItemBothMetadataAndDescription)
	})

	t.Run("target", func(t *testing.T) {
		t.Run("comment", func(t *testing.T) {
			testBCTargetResource(t, "comment")
		})

		t.Run("description", func(t *testing.T) {
			testBCTargetResource(t, "description")
		})

		t.Run("both", testBCTargetBothMetadataAndDescription)
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

	itemName := "test_bc_secret_" + field
	itemPath := testPath(itemName)
	defer deleteItem(t, itemPath)

	config := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path 	= "%v"
			value	= "1234"
			%s 		= "aaa"
		}
	`, itemName, itemPath, field)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path 	= "%v"
			value 	= "1234"
			%s 		= ""
		}
	`, itemName, itemPath, field)

	testItemDescriptionBC(t, config, "aaa", configUpdate, "", itemPath)
}

func testBCKeyResource(t *testing.T, field string) {
	t.Parallel()

	itemName := "test_bc_key_" + field
	itemPath := testPath(itemName)
	defer deleteItem(t, itemPath)

	config := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 	= "%v"
			alg 	= "RSA1024"
			%s 		= "aaa"
		}
	`, itemName, itemPath, field)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 	= "%v"
			alg 	= "RSA1024"
			%s 		= ""
		}
	`, itemName, itemPath, field)

	testItemDescriptionBC(t, config, "aaa", configUpdate, "", itemPath)
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

	testTargetDescriptionBC(t, config, "aaa", configUpdate, "", targetPath)
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

	testRoleDescriptionBC(t, config, "aaa", configUpdate, "", rolePath)
}

func testBCItemBothMetadataAndDescription(t *testing.T) {
	t.Parallel()

	itemName := "test_bc_item_both"
	itemPath := testPath(itemName)
	defer deleteItem(t, itemPath)

	config := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 		= "%v"
			alg 		= "RSA1024"
			description = "aaa"
		}
	`, itemName, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 		= "%v"
			alg 		= "RSA1024"
			metadata 	= "bbb"
		}
	`, itemName, itemPath)

	testItemDescriptionBC(t, config, "aaa", configUpdate, "bbb", itemPath)
}

func testBCTargetBothMetadataAndDescription(t *testing.T) {
	t.Parallel()

	targetName := "test_bc_item_both"
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
			description = "aaa"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 		= "%v"
			db_type   	= "mysql"
			user_name 	= "user1"
			pwd 		= "1234"
			host 		= "127.0.0.1"
			port 		= "3306"
			db_name 	= "mysql"
			comment 	= "bbb"
		}
	`, targetName, targetPath)

	testTargetDescriptionBC(t, config, "aaa", configUpdate, "bbb", targetPath)
}

func testItemDescriptionBC(t *testing.T, config, expDescription,
	configUpdate, expDescriptionUpdate, itemPath string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkItemDescriptionRemotely(itemPath, expDescription),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkItemDescriptionRemotely(itemPath, expDescriptionUpdate),
				),
			},
		},
	})
}

func checkItemDescriptionRemotely(path, expDescription string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.DescribeItem{
			Name:         path,
			ShowVersions: akeyless.PtrBool(false),
			Token:        &token,
		}

		out, _, err := client.DescribeItem(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}
		if out.ItemMetadata == nil {
			return fmt.Errorf("description is nil")
		}
		result := *out.ItemMetadata
		if result != expDescription {
			return fmt.Errorf("description is not as expected - result: %s, expect: %s",
				result, expDescription)
		}
		return nil
	}
}

func testTargetDescriptionBC(t *testing.T, config, expDescription,
	configUpdate, expDescriptionUpdate, itemPath string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkTargetDescriptionRemotely(itemPath, expDescription),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkTargetDescriptionRemotely(itemPath, expDescriptionUpdate),
				),
			},
		},
	})
}

func checkTargetDescriptionRemotely(path, expDescription string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GetTargetDetails{
			Name:  path,
			Token: &token,
		}

		out, _, err := client.GetTargetDetails(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}
		if out.Target == nil {
			return fmt.Errorf("target output is nil")
		}
		if out.Target.Comment == nil {
			if expDescription != "" {
				return fmt.Errorf("description is not as expected - result: nil, expect: %s",
					expDescription)
			}
			return nil
		}

		result := *out.Target.Comment
		if result != expDescription {
			return fmt.Errorf("description is not as expected - result: %s, expect: %s",
				result, expDescription)
		}
		return nil
	}
}

func testRoleDescriptionBC(t *testing.T, config, expDescription,
	configUpdate, expDescriptionUpdate, itemPath string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkRoleDescriptionRemotely(itemPath, expDescription),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkRoleDescriptionRemotely(itemPath, expDescriptionUpdate),
				),
			},
		},
	})
}

func checkRoleDescriptionRemotely(roleName, expDescription string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GetRole{
			Name:  roleName,
			Token: &token,
		}

		out, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}
		if out.Comment == nil {
			return fmt.Errorf("description is nil")
		}
		result := *out.Comment
		if result != expDescription {
			return fmt.Errorf("description is not as expected - result: %s, expect: %s",
				result, expDescription)
		}
		return nil
	}
}
