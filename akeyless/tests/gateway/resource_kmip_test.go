package gateway

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestKMIPServerAndClientResources(t *testing.T) {
	t.Skip("TODO: This test may need to be removed")
	t.Parallel()

	serverRoot := testPath("kmip-server")
	clientName := testPath("kmip-client")

	config := fmt.Sprintf(`
		resource "akeyless_kmip_server" "server" {
			hostname           = "kmip.example.com"
			root               = "%s"
			certificate_ttl    = 90
			expiration_event_in = ["10"]
		}

		resource "akeyless_kmip_client" "client" {
			name                        = "%s"
			activate_keys_on_creation   = true
			certificate_ttl             = 90
			expiration_event_in         = ["10"]
			depends_on                  = [akeyless_kmip_server.server]
		}
	`, serverRoot, clientName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_kmip_server" "server" {
			hostname           = "kmip.example.com"
			root               = "%s"
			certificate_ttl    = 90
			expiration_event_in = ["15"]
		}

		resource "akeyless_kmip_client" "client" {
			name                        = "%s"
			activate_keys_on_creation   = true
			certificate_ttl             = 90
			expiration_event_in         = ["15"]
			depends_on                  = [akeyless_kmip_server.server]
		}
	`, serverRoot, clientName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_kmip_server.server", "hostname", "kmip.example.com"),
					resource.TestCheckResourceAttr("akeyless_kmip_server.server", "root", serverRoot),
					resource.TestCheckResourceAttr("akeyless_kmip_server.server", "expiration_event_in.#", "1"),
					resource.TestCheckResourceAttr("akeyless_kmip_client.client", "name", clientName),
					resource.TestCheckResourceAttr("akeyless_kmip_client.client", "activate_keys_on_creation", "true"),
					resource.TestCheckResourceAttr("akeyless_kmip_client.client", "expiration_event_in.#", "1"),
					resource.TestCheckResourceAttrSet("akeyless_kmip_client.client", "client_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_kmip_server.server", "expiration_event_in.#", "1"),
					resource.TestCheckResourceAttr("akeyless_kmip_client.client", "expiration_event_in.#", "1"),
				),
			},
		},
	})
}
