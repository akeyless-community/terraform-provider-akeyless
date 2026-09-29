package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestTargetAerospikeResource(t *testing.T) {
	// TODO: Re-enable after Aerospike target validation receives BYPASS_DRY_RUN.
	t.Skip("Aerospike target creation requires a reachable Aerospike service")
	testutils.SkipIfNoGateway(t)

	targetName := "aerospike_target"
	targetPath := testPath(targetName)
	config := fmt.Sprintf(`
		resource "akeyless_target_aerospike" "%v" {
			name           = "%v"
			hostname       = "127.0.0.1"
			port           = "3000"
			namespace      = "test"
			admin_username = "admin"
			password       = "password"
			description    = "test aerospike target"
		}
	`, targetName, targetPath)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_aerospike" "%v" {
			name           = "%v"
			hostname       = "127.0.0.1"
			port           = "3000"
			namespace      = "test"
			admin_username = "admin"
			password       = "password"
			description    = "updated aerospike target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetGlobalSignResource(t *testing.T) {
	// TODO: Re-enable after CI has GlobalSign credentials or target validation receives BYPASS_DRY_RUN.
	t.Skip("GlobalSign target creation validates external credentials")
	testutils.SkipIfNoGateway(t)

	targetName := "globalsign_target"
	targetPath := testPath(targetName)
	config := fmt.Sprintf(`
		resource "akeyless_target_globalsign" "%v" {
			name               = "%v"
			timeout            = "1m0s"
			username           = "user1"
			password           = "pass1"
			profile_id         = "id1"
			contact_first_name = "first1"
			contact_last_name  = "last1"
			contact_phone      = "phone1"
			contact_email      = "ku@ku1.io"
			description        = "desc1"
		}
	`, targetName, targetPath)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_globalsign" "%v" {
			name               = "%v"
			timeout            = "2m30s"
			username           = "user2"
			password           = "pass2"
			profile_id         = "id2"
			contact_first_name = "first2"
			contact_last_name  = "last2"
			contact_phone      = "phone2"
			contact_email      = "ku@ku2.io"
			description        = "desc2"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetDataSourceGlobalSign(t *testing.T) {
	// TODO: Re-enable after CI has GlobalSign credentials or target validation receives BYPASS_DRY_RUN.
	t.Skip("GlobalSign target creation validates external credentials")
	testutils.SkipIfNoGateway(t)

	targetName := "target-globalsign"
	targetPath := testPath(targetName)
	targetDetailsType := "globalsign_target_details"
	expect := map[string]any{
		"timeout":            "1m",
		"username":           "user1",
		"password":           "1234",
		"profile_id":         "id1",
		"contact_first_name": "first1",
		"contact_last_name":  "last1",
		"contact_phone":      "phone1",
		"contact_email":      "k@k.io",
	}
	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	config := fmt.Sprintf(`
		data "akeyless_target_details" "globalsign" {
			name = "%v"
		}
	`, targetPath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.akeyless_target_details.globalsign", "value.globalsign_target_details"),
				),
			},
		},
	})
}

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

func TestHashivaultTargetResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "hashivault_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_hashivault" "%v" {
			name        = "%v"
			hashi_url   = "https://vault.example.com"
			vault_token = "test-token"
			description = "Test Hashivault target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_hashivault" "%v" {
			name        = "%v"
			hashi_url   = "https://vault2.example.com"
			vault_token = "test-token2"
			description = "Updated Hashivault target"
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
			name        = "%v"
			api_key     = "sk-test123"
			openai_url  = "https://api.openai.com"
			description = "Test OpenAI target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name        = "%v"
			api_key     = "sk-test456"
			openai_url  = "https://api.openai.com"
			description = "Updated OpenAI target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

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
