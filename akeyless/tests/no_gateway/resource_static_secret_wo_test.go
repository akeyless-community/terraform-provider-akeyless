package no_gateway

import (
	"context"
	"fmt"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// checkSecretValueRemotely verifies the value stored in Akeyless.
func checkSecretValueRemotely(path, wantValue string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		client, token, err := testutils.GetClient()
		if err != nil {
			return err
		}

		gsvBody := akeyless_api.GetSecretValue{
			Names: []string{path},
			Token: &token,
		}

		out, _, err := client.GetSecretValue(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}

		got, _ := out[path].(string)
		if got != wantValue {
			return fmt.Errorf("secret %s: got value %q, want %q", path, got, wantValue)
		}
		return nil
	}
}

// Verify value_wo writes the secret and keeps it out of state.
func TestStaticSecretWriteOnly(t *testing.T) {
	t.Parallel()

	secretName := "test_secret_wo"
	secretPath := testPath(secretName)
	resourceAddr := "akeyless_static_secret." + secretName

	configLegacy := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path  = "%v"
			value = "legacy-secret"
		}
	`, secretName, secretPath)

	config := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path             = "%v"
			value_wo         = "write-only-secret-v1"
			value_wo_version = 1
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_static_secret" "%v" {
			path             = "%v"
			value_wo         = "write-only-secret-v2"
			value_wo_version = 2
		}
	`, secretName, secretPath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkStaticSecretDestroyed,
		Steps: []resource.TestStep{
			{
				Config: configLegacy,
				Check:  checkSecretValueRemotely(secretPath, "legacy-secret"),
			},
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkSecretValueRemotely(secretPath, "write-only-secret-v1"),
					testutils.CheckSecretNotInState(resourceAddr, "value"),
					resource.TestCheckNoResourceAttr(resourceAddr, "value_wo"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkSecretValueRemotely(secretPath, "write-only-secret-v2"),
					testutils.CheckSecretNotInState(resourceAddr, "value"),
				),
			},
		},
	})
}
