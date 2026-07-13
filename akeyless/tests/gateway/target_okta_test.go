package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestOktaTargetResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "okta_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_okta" "%v" {
			name        = "%v"
			url         = "https://example.okta.com"
			api_token   = "okta-token"
			description = "Test Okta target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_okta" "%v" {
			name        = "%v"
			url         = "https://example2.okta.com"
			api_token   = "okta-token-2"
			description = "Updated Okta target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}
