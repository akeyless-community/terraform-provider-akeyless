package gateway

import (
	"fmt"
	"testing"

	akeyless_provider "github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestHashivaultTargetResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "hashivault_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_hashivault" "%v" {
			name 				= "%v"
			lock_on_read 		= "true"
			lock_ttl 			= "5"
			rotate_on_unlock 	= "true"
			hashi_url 			= "https://vault.example.com"
			vault_token 		= "test-token"
			description 		= "Test Hashivault target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_hashivault" "%v" {
			name 				= "%v"
			lock_on_read 		= "false"
			lock_ttl 			= "10"
			rotate_on_unlock 	= "false"
			hashi_url 			= "https://vault2.example.com"
			vault_token 		= "test-token2"
			description 		= "Updated Hashivault target"
		}
	`, targetName, targetPath)

	resourceName := "akeyless_target_hashivault." + targetName
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      testutils.CheckTargetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(targetPath),
					resource.TestCheckResourceAttr(resourceName, "lock_on_read", "true"),
					resource.TestCheckResourceAttr(resourceName, "lock_ttl", "5"),
					resource.TestCheckResourceAttr(resourceName, "rotate_on_unlock", "true"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(targetPath),
					resource.TestCheckResourceAttr(resourceName, "lock_on_read", "false"),
					resource.TestCheckResourceAttr(resourceName, "lock_ttl", "10"),
					resource.TestCheckResourceAttr(resourceName, "rotate_on_unlock", "false"),
				),
			},
		},
	})
}

func TestOpenAITargetResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "openai_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name                      = "%v"
			lock_on_read              = "true"
			lock_ttl                  = "5"
			rotate_on_unlock          = "true"
			codex_oauth_mode          = "chatgpt_oauth"
			codex_oauth_access_token  = "access-token"
			codex_oauth_account_id    = "account-id"
			codex_oauth_refresh_token = "refresh-token"
			description               = "Test OpenAI target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name                      = "%v"
			lock_on_read              = "false"
			lock_ttl                  = "10"
			rotate_on_unlock          = "false"
			codex_oauth_mode          = "chatgpt_oauth"
			codex_oauth_access_token  = "updated-access-token"
			codex_oauth_account_id    = "updated-account-id"
			codex_oauth_refresh_token = "updated-refresh-token"
			description               = "Updated OpenAI target"
		}
	`, targetName, targetPath)

	resourceName := "akeyless_target_openai." + targetName
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      testutils.CheckTargetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(targetPath),
					resource.TestCheckResourceAttr(resourceName, "lock_on_read", "true"),
					resource.TestCheckResourceAttr(resourceName, "lock_ttl", "5"),
					resource.TestCheckResourceAttr(resourceName, "rotate_on_unlock", "true"),
					resource.TestCheckResourceAttr(resourceName, "codex_oauth_mode", "chatgpt_oauth"),
					resource.TestCheckResourceAttr(resourceName, "codex_oauth_access_token", "access-token"),
					resource.TestCheckResourceAttr(resourceName, "codex_oauth_account_id", "account-id"),
					resource.TestCheckResourceAttr(resourceName, "codex_oauth_refresh_token", "refresh-token"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(targetPath),
					resource.TestCheckResourceAttr(resourceName, "lock_on_read", "false"),
					resource.TestCheckResourceAttr(resourceName, "lock_ttl", "10"),
					resource.TestCheckResourceAttr(resourceName, "rotate_on_unlock", "false"),
					resource.TestCheckResourceAttr(resourceName, "codex_oauth_mode", "chatgpt_oauth"),
					resource.TestCheckResourceAttr(resourceName, "codex_oauth_access_token", "updated-access-token"),
					resource.TestCheckResourceAttr(resourceName, "codex_oauth_account_id", "updated-account-id"),
					resource.TestCheckResourceAttr(resourceName, "codex_oauth_refresh_token", "updated-refresh-token"),
				),
			},
		},
	})
}

func TestOpenAITargetCodexOAuthSchema(t *testing.T) {
	schema := akeyless_provider.Provider().ResourcesMap["akeyless_target_openai"].Schema

	for _, fieldName := range []string{"codex_oauth_access_token", "codex_oauth_refresh_token"} {
		if field := schema[fieldName]; field == nil || !field.Sensitive {
			t.Errorf("%s must be sensitive", fieldName)
		}
	}
}
