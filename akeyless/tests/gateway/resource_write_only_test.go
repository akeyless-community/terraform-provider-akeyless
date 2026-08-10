package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// Verify mysql_password_wo writes the secret and version changes update it.
func TestDynamicSecretMysqlWriteOnly(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-db-wo"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "mysql",
		"user_name": "test",
		"pwd":       "test",
		"host":      "127.0.0.1",
		"port":      "3306",
		"db_name":   "test",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_mysql_wo_test"
	dsPath := testPath(dsName)
	resourceAddr := "akeyless_dynamic_secret_mysql." + dsName

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

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckItemExistsRemotely(dsPath),
					testutils.CheckSecretNotInState(resourceAddr, "mysql_password"),
					resource.TestCheckNoResourceAttr(resourceAddr, "mysql_password_wo"),
					resource.TestCheckResourceAttr(resourceAddr, "mysql_password_wo_version", "1"),
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
		"user_name": "test",
		"pwd":       "test",
		"host":      "127.0.0.1",
		"port":      "3306",
		"db_name":   "test",
	})
	t.Cleanup(func() { testutils.DeleteTarget(t, targetPath) })

	rsName := "rs_mysql_wo_test"
	rsPath := testPath(rsName)
	addr := "akeyless_rotated_secret_mysql." + rsName

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

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
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
				),
			},
		},
	})
}
