package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestStaticSecretSyncResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	secretName := "test_static_secret_for_sync"
	secretPath := testPath(secretName)
	targetName := "target_hashi_for_sync"
	targetPath := testPath(targetName)
	uscName := "usc_for_sync"
	uscPath := testPath(uscName)
	remoteSecretName := "secret/data/example"

	config := fmt.Sprintf(`
        resource "akeyless_target_hashivault" "%v" {
            name        = "%v"
            hashi_url   = "http://127.0.0.1:8200"
            vault_token = "test"
        }

        resource "akeyless_usc" "%v" {
            name                = "%v"
            target_to_associate = akeyless_target_hashivault.%v.name
            depends_on          = [akeyless_target_hashivault.%v]
        }

        resource "akeyless_static_secret" "%v" {
            path   = "%v"
            value  = "{\"k\":\"v\"}"
            format = "json"
        }

        resource "akeyless_static_secret_sync" "sync" {
            name               = akeyless_static_secret.%v.path
            usc_name           = akeyless_usc.%v.name
            remote_secret_name = "%v"
            depends_on         = [akeyless_static_secret.%v, akeyless_usc.%v]
        }
    `, targetName, targetPath,
		uscName, uscPath, targetName, targetName,
		secretName, secretPath,
		secretName, uscName, remoteSecretName, secretName, uscName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
			},
		},
	})
}
