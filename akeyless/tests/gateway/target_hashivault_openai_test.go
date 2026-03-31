package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestHashivaultTargetResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()
	targetName := "hashivault_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_hashivault" "%v" {
			name 				= "%v"
			hashi_url 			= "https://vault.example.com"
			vault_token 		= "test-token"
			description 		= "Test Hashivault target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_hashivault" "%v" {
			name 				= "%v"
			hashi_url 			= "https://vault2.example.com"
			vault_token 		= "test-token2"
			description 		= "Updated Hashivault target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestOpenAITargetResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()
	targetName := "openai_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name 				= "%v"
			api_key 			= "sk-test123"
			description 		= "Test OpenAI target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name 				= "%v"
			api_key 			= "sk-test456"
			description 		= "Updated OpenAI target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}
