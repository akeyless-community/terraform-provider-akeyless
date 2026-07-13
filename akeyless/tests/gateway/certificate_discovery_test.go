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

	config := fmt.Sprintf(`
		resource "akeyless_certificate_discovery" "%v" {
			hosts                = "127.0.0.1"
			port_ranges          = "443"
			target_location      = "%v"
			expiration_event_in  = ["30", "10"]
			debug                = true
		}
	`, name, folder)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(fmt.Sprintf("akeyless_certificate_discovery.%v", name), "id"),
					resource.TestCheckResourceAttr(fmt.Sprintf("akeyless_certificate_discovery.%v", name), "hosts", "127.0.0.1"),
					resource.TestCheckResourceAttr(fmt.Sprintf("akeyless_certificate_discovery.%v", name), "port_ranges", "443"),
					resource.TestCheckResourceAttr(fmt.Sprintf("akeyless_certificate_discovery.%v", name), "target_location", folder),
					resource.TestCheckResourceAttr(fmt.Sprintf("akeyless_certificate_discovery.%v", name), "expiration_event_in.#", "2"),
				),
			},
		},
	})
}
