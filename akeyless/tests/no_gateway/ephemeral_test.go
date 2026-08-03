package no_gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// TestStaticSecretEphemeral opens an ephemeral static secret and feeds its
// value into another secret via value_wo — proving Open works and the secret
// never lands in state as a data source.
func TestStaticSecretEphemeral(t *testing.T) {
	testutils.SkipIfTerraformBelow(t, "1.11.0")
	t.Parallel()

	srcPath := testPath("ephemeral_static_src")
	dstPath := testPath("ephemeral_static_dst")
	want := "ephemeral-static-value"

	config := fmt.Sprintf(`
		resource "akeyless_static_secret" "src" {
			path             = "%v"
			value_wo         = "%v"
			value_wo_version = 1
		}

		ephemeral "akeyless_static_secret" "e" {
			path       = akeyless_static_secret.src.path
			depends_on = [akeyless_static_secret.src]
		}

		resource "akeyless_static_secret" "dst" {
			path             = "%v"
			value_wo         = ephemeral.akeyless_static_secret.e.value
			value_wo_version = 1
		}
	`, srcPath, want, dstPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testutils.NewMuxProtoV6ProviderFactories(),
		CheckDestroy:             checkStaticSecretDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkSecretValueRemotely(dstPath, want),
					resource.TestCheckResourceAttr("akeyless_static_secret.src", "value", ""),
					resource.TestCheckResourceAttr("akeyless_static_secret.dst", "value", ""),
				),
			},
		},
	})
}
