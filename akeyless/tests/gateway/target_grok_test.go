package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestGrokTargetResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "grok_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_grok" "%v" {
			name        = "%v"
			api_key     = "xai-key"
			grok_url    = "https://api.x.ai"
			team_id     = "team-1"
			description = "Test Grok target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_grok" "%v" {
			name        = "%v"
			api_key     = "xai-key-2"
			grok_url    = "https://api.x.ai/v2"
			team_id     = "team-2"
			description = "Updated Grok target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}
