package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestCertificateDiscoveryResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "cert_discovery"
	folder := testPath(name)
	resourceName := fmt.Sprintf("akeyless_certificate_discovery.%v", name)

	config := fmt.Sprintf(`
		resource "akeyless_certificate_discovery" "%v" {
			hosts                = "127.0.0.1"
			port_ranges          = "443"
			target_location      = "%v"
			expiration_event_in  = ["30", "10"]
		}
	`, name, folder)

	// All schema fields are ForceNew — "update" is destroy+recreate.
	configUpdate := fmt.Sprintf(`
		resource "akeyless_certificate_discovery" "%v" {
			hosts                = "127.0.0.1"
			port_ranges          = "8443"
			target_location      = "%v"
			expiration_event_in  = ["30", "10"]
		}
	`, name, folder)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "hosts", "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, "port_ranges", "443"),
					resource.TestCheckResourceAttr(resourceName, "target_location", folder),
					resource.TestCheckResourceAttr(resourceName, "expiration_event_in.#", "2"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "hosts", "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, "port_ranges", "8443"),
					resource.TestCheckResourceAttr(resourceName, "target_location", folder),
					resource.TestCheckResourceAttr(resourceName, "expiration_event_in.#", "2"),
				),
			},
		},
	})
}
