package akeyless

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestStaticSecretSyncResource(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

	secretName := "test_static_secret_for_sync"
	secretPath := testPath(secretName)
	uscName := "test-usc-for-sync"
	remoteSecretName := "secret/data/example"

	config := fmt.Sprintf(`
        resource "akeyless_static_secret" "%v" {
            path   = "%v"
            value  = "{\"k\":\"v\"}"
            format = "json"
        }

        resource "akeyless_static_secret_sync" "sync" {
            name               = akeyless_static_secret.%v.path
            usc_name           = "%v"
            remote_secret_name = "%v"
            depends_on         = [akeyless_static_secret.%v]
        }
    `, secretName, secretPath, secretName, uscName, remoteSecretName, secretName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
			},
		},
	})
}
