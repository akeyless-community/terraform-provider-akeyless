package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestGatewayMigrationHashiResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	testutils.SkipIfNoVault(t)

	migrationName := "test-hashi-migration"
	migrationPath := testPath(migrationName)

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_hashi" "mig" {
			name               = "%v"
			target_location    = "%v"
			hashi_url          = "%v"
			hashi_token        = "%v"
			hashi_json         = "true"
			hashi_metadata_mode = "minimal"
		}
	`, migrationName, migrationPath, HashiVaultUrl, HashiVaultToken)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_hashi" "mig" {
			name               = "%v"
			target_location    = "%v"
			hashi_url          = "%v"
			hashi_token        = "%v"
			hashi_json         = "true"
			hashi_metadata_mode = "full"
		}
	`, migrationName, migrationPath, HashiVaultUrl, HashiVaultToken)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_gateway_migration_hashi.mig", "hashi_metadata_mode", "minimal"),
					resource.TestCheckResourceAttr("akeyless_gateway_migration_hashi.mig", "hashi_json", "true"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_gateway_migration_hashi.mig", "hashi_metadata_mode", "full"),
				),
			},
		},
	})
}
