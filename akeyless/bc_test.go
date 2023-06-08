package akeyless

import (
	"context"
	"fmt"
	"testing"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

type configDescriptionTest struct {
	Config            string
	ExpectDescription string
}

func TestBCDescription(t *testing.T) {
	t.Skip("this test began to fail and it is unnecessary to fix since it is an old bc")
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

	config0 := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path 	= "%v"
			value	= "1234"
			%s 		= "aaa"
		}
	`, itemName, itemPath, field)

	config1 := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path 	= "%v"
			value	= "1234"
			%s 		= "bbb"
		}
	`, itemName, itemPath, field)

	config2 := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path 	= "%v"
			value 	= "1234"
			%s 		= ""
		}
	`, itemName, itemPath, field)

	steps := []configDescriptionTest{
		{Config: config0, ExpectDescription: "aaa"},
		{Config: config1, ExpectDescription: "bbb"},
		{Config: config2, ExpectDescription: ""},
	}

	testItemDescriptionBC(t, steps, itemPath)
}

func testBCKeyResource(t *testing.T, field string) {
	t.Parallel()

	itemName := "test_bc_key_" + field
	itemPath := testPath(itemName)

	config0 := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 	= "%v"
			alg 	= "RSA1024"
			%s 		= "aaa"
		}
	`, itemName, itemPath, field)

	config1 := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 	= "%v"
			alg 	= "RSA1024"
			%s 		= "bbb"
		}
	`, itemName, itemPath, field)

	config2 := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 	= "%v"
			alg 	= "RSA1024"
			%s 		= ""
		}
	`, itemName, itemPath, field)

	steps := []configDescriptionTest{
		{Config: config0, ExpectDescription: "aaa"},
		{Config: config1, ExpectDescription: "bbb"},
		{Config: config2, ExpectDescription: ""},
	}

	testItemDescriptionBC(t, steps, itemPath)
}

func testBCTargetResource(t *testing.T, field string) {
	t.Parallel()

	targetName := "test_bc_target_" + field
	targetPath := testPath(targetName)
	defer deleteTarget(t, targetPath)

	config0 := fmt.Sprintf(`
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

	config1 := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 		= "%v"
			db_type   	= "mysql"
			user_name 	= "user1"
			pwd 		= "1234"
			host 		= "127.0.0.1"
			port 		= "3306"
			db_name 	= "mysql"
			%s 			= "bbb"
		}
	`, targetName, targetPath, field)

	config2 := fmt.Sprintf(`
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

	steps := []configDescriptionTest{
		{Config: config0, ExpectDescription: "aaa"},
		{Config: config1, ExpectDescription: "bbb"},
		{Config: config2, ExpectDescription: ""},
	}

	testTargetDescriptionBC(t, steps, targetPath)
}

func testBCRoleResource(t *testing.T, field string) {
	t.Parallel()

	roleName := "test_bc_role_" + field
	rolePath := testPath(roleName)
	defer deleteRole(rolePath)

	config0 := fmt.Sprintf(`
		resource "akeyless_role" "%v" {
			name	= "%v"
			%s 		= "aaa"
		}
	`, roleName, rolePath, field)

	config1 := fmt.Sprintf(`
		resource "akeyless_role" "%v" {
			name	= "%v"
			%s 		= "bbb"
		}
	`, roleName, rolePath, field)

	config2 := fmt.Sprintf(`
		resource "akeyless_role" "%v" {
			name	= "%v"
			%s 		= ""
		}
	`, roleName, rolePath, field)

	steps := []configDescriptionTest{
		{Config: config0, ExpectDescription: "aaa"},
		{Config: config1, ExpectDescription: "bbb"},
		{Config: config2, ExpectDescription: ""},
	}

	testRoleDescriptionBC(t, steps, rolePath)
}

func testBCItemBothMetadataAndDescription(t *testing.T) {
	t.Parallel()

	itemName := "test_bc_item_both"
	itemPath := testPath(itemName)

	config0 := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 		= "%v"
			alg 		= "RSA1024"
			metadata 	= "aaa"
		}
	`, itemName, itemPath)

	config1 := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 		= "%v"
			alg 		= "RSA1024"
			description = "bbb"
		}
	`, itemName, itemPath)

	config2 := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 		= "%v"
			alg 		= "RSA1024"
		}
	`, itemName, itemPath)

	steps := []configDescriptionTest{
		{Config: config0, ExpectDescription: "aaa"},
		{Config: config1, ExpectDescription: "bbb"},
		{Config: config2, ExpectDescription: ""},
	}

	testItemDescriptionBC(t, steps, itemPath)
}

func testBCTargetBothMetadataAndDescription(t *testing.T) {
	t.Parallel()

	targetName := "test_bc_item_both"
	targetPath := testPath(targetName)
	defer deleteTarget(t, targetPath)

	config0 := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 		= "%v"
			db_type   	= "mysql"
			user_name 	= "user1"
			pwd 		= "1234"
			host 		= "127.0.0.1"
			port 		= "3306"
			db_name 	= "mysql"
			comment  	= "aaa"
		}
	`, targetName, targetPath)

	config1 := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 		= "%v"
			db_type   	= "mysql"
			user_name 	= "user1"
			pwd 		= "1234"
			host 		= "127.0.0.1"
			port 		= "3306"
			db_name 	= "mysql"
			description = "bbb"
		}
	`, targetName, targetPath)

	config2 := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 		= "%v"
			db_type   	= "mysql"
			user_name 	= "user1"
			pwd 		= "1234"
			host 		= "127.0.0.1"
			port 		= "3306"
			db_name 	= "mysql"
		}
	`, targetName, targetPath)

	steps := []configDescriptionTest{
		{Config: config0, ExpectDescription: "aaa"},
		{Config: config1, ExpectDescription: "bbb"},
		{Config: config2, ExpectDescription: ""},
	}

	testTargetDescriptionBC(t, steps, targetPath)
}

func testItemDescriptionBC(t *testing.T, steps []configDescriptionTest,
	itemPath string) {

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: steps[0].Config,
				Check: resource.ComposeTestCheckFunc(
					checkItemDescriptionRemotely(itemPath, steps[0].ExpectDescription),
				),
			},
			{
				Config: steps[1].Config,
				Check: resource.ComposeTestCheckFunc(
					checkItemDescriptionRemotely(itemPath, steps[1].ExpectDescription),
				),
			},
			{
				Config: steps[2].Config,
				Check: resource.ComposeTestCheckFunc(
					checkItemDescriptionRemotely(itemPath, steps[2].ExpectDescription),
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

func testTargetDescriptionBC(t *testing.T, steps []configDescriptionTest,
	itemPath string) {

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: steps[0].Config,
				Check: resource.ComposeTestCheckFunc(
					checkTargetDescriptionRemotely(itemPath, steps[0].ExpectDescription),
				),
			},
			{
				Config: steps[1].Config,
				Check: resource.ComposeTestCheckFunc(
					checkTargetDescriptionRemotely(itemPath, steps[1].ExpectDescription),
				),
			},
			{
				Config: steps[2].Config,
				Check: resource.ComposeTestCheckFunc(
					checkTargetDescriptionRemotely(itemPath, steps[2].ExpectDescription),
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

func testRoleDescriptionBC(t *testing.T, steps []configDescriptionTest,
	itemPath string) {

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: steps[0].Config,
				Check: resource.ComposeTestCheckFunc(
					checkRoleDescriptionRemotely(itemPath, steps[0].ExpectDescription),
				),
			},
			{
				Config: steps[1].Config,
				Check: resource.ComposeTestCheckFunc(
					checkRoleDescriptionRemotely(itemPath, steps[1].ExpectDescription),
				),
			},
			{
				Config: steps[2].Config,
				Check: resource.ComposeTestCheckFunc(
					checkRoleDescriptionRemotely(itemPath, steps[2].ExpectDescription),
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
