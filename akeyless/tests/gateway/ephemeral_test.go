package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// TestDynamicSecretEphemeral opens ephemeral dynamic-secret creds and writes
// them into a static secret via value_wo — proving Open works without a data
// source landing the value in state.
//
// Two steps are required: ephemeral Open runs during plan, so the dynamic
// secret must already exist before the ephemeral block is introduced.
func TestDynamicSecretEphemeral(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetPath := testPath("test-target-db-ephemeral")
	testutils.CreateTargetByType(t, targetPath, "db_target_details", map[string]any{
		"db_type":   "mysql",
		"user_name": testutils.DockerMysqlUser,
		"pwd":       testutils.DockerMysqlPassword,
		"host":      testutils.DockerMysqlHost,
		"port":      testutils.DockerMysqlPort,
		"db_name":   testutils.DockerMysqlDB,
	})
	t.Cleanup(func() { testutils.DeleteTarget(t, targetPath) })

	dsPath := testPath("ds_mysql_ephemeral")
	dstPath := testPath("ephemeral_ds_dst")

	createDS := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mysql" "ds" {
			name        = "%v"
			target_name = "%v"
			user_ttl    = "5m"
		}
	`, dsPath, targetPath)

	withEphemeral := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mysql" "ds" {
			name        = "%v"
			target_name = "%v"
			user_ttl    = "5m"
		}

		ephemeral "akeyless_dynamic_secret" "e" {
			path = akeyless_dynamic_secret_mysql.ds.name
		}

		resource "akeyless_static_secret" "dst" {
			path             = "%v"
			value_wo         = ephemeral.akeyless_dynamic_secret.e.value
			value_wo_version = 1
		}
	`, dsPath, targetPath, dstPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testutils.NewMuxProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: createDS,
				Check:  testutils.CheckItemExistsRemotely(dsPath),
			},
			{
				Config: withEphemeral,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckItemExistsRemotely(dsPath),
					testutils.CheckItemExistsRemotely(dstPath),
					testutils.CheckSecretNotInState("akeyless_static_secret.dst", "value"),
				),
			},
		},
	})
}
