package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestKeycloakTargetResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "keycloak_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_keycloak" "%v" {
			name          = "%v"
			url           = "https://keycloak.example.com"
			realm         = "master"
			client_id     = "client"
			client_secret = "secret"
			description   = "Test Keycloak target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_keycloak" "%v" {
			name          = "%v"
			url           = "https://keycloak2.example.com"
			realm         = "realm2"
			client_id     = "client2"
			client_secret = "secret2"
			description   = "Updated Keycloak target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}
