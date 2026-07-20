package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestAnthropicTargetResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "anthropic_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_anthropic" "%v" {
			name          = "%v"
			api_key       = "sk-ant-test"
			anthropic_url = "https://api.anthropic.com"
			description   = "Test Anthropic target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_anthropic" "%v" {
			name          = "%v"
			api_key       = "sk-ant-test-2"
			anthropic_url = "https://api.anthropic.com/v2"
			description   = "Updated Anthropic target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}
