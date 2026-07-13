package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestCustomDnsTargetResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "custom_dns_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_custom_dns" "%v" {
			name          = "%v"
			provider_type = "route53"
			dns_parameter = {
				access_key = "AKIA"
				secret_key = "secret"
			}
			description = "Test Custom DNS target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_custom_dns" "%v" {
			name          = "%v"
			provider_type = "cloudflare"
			dns_parameter = {
				api_token = "cf-token"
			}
			description = "Updated Custom DNS target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}
