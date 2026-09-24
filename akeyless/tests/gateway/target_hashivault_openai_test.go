package gateway

import (
	"fmt"
	"testing"

	akeyless_provider "github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestHashivaultTargetResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

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

	targetName := "openai_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name 				= "%v"
			codex_oauth_mode 		= "chatgpt_oauth"
			codex_oauth_access_token 	= "access-token"
			codex_oauth_account_id 	= "account-id"
			codex_oauth_refresh_token 	= "refresh-token"
			description 		= "Test OpenAI target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name 				= "%v"
			codex_oauth_mode 		= "chatgpt_oauth"
			codex_oauth_access_token 	= "updated-access-token"
			codex_oauth_account_id 	= "updated-account-id"
			codex_oauth_refresh_token 	= "updated-refresh-token"
			description 		= "Updated OpenAI target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestOpenAITargetCodexOAuthSchema(t *testing.T) {
	schema := akeyless_provider.Provider().ResourcesMap["akeyless_target_openai"].Schema

	for _, fieldName := range []string{"codex_oauth_access_token", "codex_oauth_refresh_token"} {
		if field := schema[fieldName]; field == nil || !field.Sensitive {
			t.Errorf("%s must be sensitive", fieldName)
		}
	}
}
