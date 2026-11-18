package gateway

import (
	"context"
	"fmt"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func rotatedSecretPassword(path string) (string, error) {
	client, token, err := testutils.GetClient()
	if err != nil {
		return "", err
	}

	out, _, err := client.GetRotatedSecretValue(context.Background()).Body(akeyless_api.GetRotatedSecretValue{
		Names: path,
		Token: &token,
	}).Execute()
	if err != nil {
		return "", err
	}

	value, ok := out["value"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("rotated secret %s: value is missing", path)
	}
	password, ok := value["password"].(string)
	if !ok {
		return "", fmt.Errorf("rotated secret %s: password is missing", path)
	}
	return password, nil
}

// Verify mysql_password_wo writes the secret and version changes update it.
func TestDynamicSecretMysqlWriteOnly(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-db-wo"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "mysql",
		"user_name": testutils.DockerMysqlUser,
		"pwd":       testutils.DockerMysqlPassword,
		"host":      testutils.DockerMysqlHost,
		"port":      testutils.DockerMysqlPort,
		"db_name":   testutils.DockerMysqlDB,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_mysql_wo_test"
	dsPath := testPath(dsName)
	resourceAddr := "akeyless_dynamic_secret_mysql." + dsName

	configLegacy := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mysql" "%v" {
			name           = "%v"
			target_name    = "%v"
			mysql_username = "%v"
			mysql_password = "%v"
			mysql_host     = "%v"
			mysql_port     = "%v"
			mysql_dbname   = "%v"
			user_ttl       = "30m"
		}
	`, dsName, dsPath, targetPath, testutils.DockerMysqlUser, testutils.DockerMysqlPassword, testutils.DockerMysqlHost, testutils.DockerMysqlPort, testutils.DockerMysqlDB)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mysql" "%v" {
			name                      = "%v"
			target_name               = "%v"
			mysql_username            = "%v"
			mysql_password_wo         = "%v"
			mysql_password_wo_version = 1
			mysql_host                = "%v"
			mysql_port                = "%v"
			mysql_dbname              = "%v"
			user_ttl                  = "30m"
		}
	`, dsName, dsPath, targetPath, testutils.DockerMysqlUser, testutils.DockerMysqlPassword, testutils.DockerMysqlHost, testutils.DockerMysqlPort, testutils.DockerMysqlDB)

	configLegacyAgain := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mysql" "%v" {
			name           = "%v"
			target_name    = "%v"
			mysql_username = "%v"
			mysql_password = "%v"
			mysql_host     = "%v"
			mysql_port     = "%v"
			mysql_dbname   = "%v"
			user_ttl       = "30m"
		}
	`, dsName, dsPath, targetPath, testutils.DockerMysqlUser, testutils.DockerMysqlPassword+"-legacy", testutils.DockerMysqlHost, testutils.DockerMysqlPort, testutils.DockerMysqlDB)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: configLegacy,
				Check:  testutils.CheckItemExistsRemotely(dsPath),
			},
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckItemExistsRemotely(dsPath),
					testutils.CheckSecretNotInState(resourceAddr, "mysql_password"),
					resource.TestCheckNoResourceAttr(resourceAddr, "mysql_password_wo"),
					resource.TestCheckResourceAttr(resourceAddr, "mysql_password_wo_version", "1"),
				),
			},
			{
				Config: configLegacyAgain,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckItemExistsRemotely(dsPath),
					resource.TestCheckResourceAttr(resourceAddr, "mysql_password", testutils.DockerMysqlPassword+"-legacy"),
				),
			},
		},
	})
}

// Verify rotated_password_wo writes the secret and version changes update it.
func TestRotatedSecretMysqlWriteOnly(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetPath := testPath("test-target-db-rs-wo")
	testutils.CreateTargetByType(t, targetPath, "db_target_details", map[string]any{
		"db_type":   "mysql",
		"user_name": testutils.DockerMysqlUser,
		"pwd":       testutils.DockerMysqlPassword,
		"host":      testutils.DockerMysqlHost,
		"port":      testutils.DockerMysqlPort,
		"db_name":   testutils.DockerMysqlDB,
	})
	t.Cleanup(func() { testutils.DeleteTarget(t, targetPath) })

	rsName := "rs_mysql_wo_test"
	rsPath := testPath(rsName)
	addr := "akeyless_rotated_secret_mysql." + rsName

	configLegacy := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mysql" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			rotated_username           = "test"
			rotated_password           = "test"
			password_length            = "9"
		}
	`, rsName, rsPath, targetPath)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mysql" "%v" {
			name                        = "%v"
			target_name                 = "%v"
			rotator_type                = "target"
			authentication_credentials  = "use-target-creds"
			rotated_username            = "test"
			rotated_password_wo         = "test"
			rotated_password_wo_version = 1
			password_length             = "9"
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mysql" "%v" {
			name                        = "%v"
			target_name                 = "%v"
			rotator_type                = "target"
			authentication_credentials  = "use-target-creds"
			rotated_username            = "test"
			rotated_password_wo         = "test-updated"
			rotated_password_wo_version = 2
			password_length             = "9"
			description                 = "wo-updated"
		}
	`, rsName, rsPath, targetPath)

	configLegacyAgain := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mysql" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			rotated_username           = "test"
			rotated_password           = "test-legacy"
			password_length            = "9"
		}
	`, rsName, rsPath, targetPath)

	configDescriptionUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mysql" "%v" {
			name                        = "%v"
			target_name                 = "%v"
			rotator_type                = "target"
			authentication_credentials  = "use-target-creds"
			rotated_username            = "test"
			rotated_password_wo         = "test-updated"
			rotated_password_wo_version = 2
			password_length             = "9"
			description                 = "description-only-update"
		}
	`, rsName, rsPath, targetPath)

	var passwordAfterWO string
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: configLegacy,
				Check:  testutils.CheckItemExistsRemotely(rsPath),
			},
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckItemExistsRemotely(rsPath),
					testutils.CheckSecretNotInState(addr, "rotated_password"),
					resource.TestCheckNoResourceAttr(addr, "rotated_password_wo"),
					resource.TestCheckResourceAttr(addr, "rotated_password_wo_version", "1"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckItemExistsRemotely(rsPath),
					testutils.CheckSecretNotInState(addr, "rotated_password"),
					resource.TestCheckResourceAttr(addr, "rotated_password_wo_version", "2"),
					func(_ *terraform.State) error {
						var err error
						passwordAfterWO, err = rotatedSecretPassword(rsPath)
						return err
					},
				),
			},
			{
				Config: configDescriptionUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckItemExistsRemotely(rsPath),
					func(_ *terraform.State) error {
						password, err := rotatedSecretPassword(rsPath)
						if err != nil {
							return err
						}
						if password != passwordAfterWO {
							return fmt.Errorf("rotated secret password changed during description update")
						}
						return nil
					},
				),
			},
			{
				Config: configLegacyAgain,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckItemExistsRemotely(rsPath),
					resource.TestCheckResourceAttr(addr, "rotated_password", "test-legacy"),
				),
			},
		},
	})
}
