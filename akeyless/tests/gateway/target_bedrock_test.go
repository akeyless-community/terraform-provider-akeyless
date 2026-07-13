package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestBedrockTargetResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "bedrock_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_bedrock" "%v" {
			name        = "%v"
			api_key     = "bedrock-key"
			bedrock_url = "https://bedrock.amazonaws.com"
			description = "Test Bedrock target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_bedrock" "%v" {
			name        = "%v"
			api_key     = "bedrock-key-2"
			bedrock_url = "https://bedrock.amazonaws.com/v2"
			description = "Updated Bedrock target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}
