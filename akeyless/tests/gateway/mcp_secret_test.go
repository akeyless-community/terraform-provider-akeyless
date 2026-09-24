package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestMcpSecretBearerTokenResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "mcp_bearer"
	path := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_mcp_secret_bearer_token" "%v" {
			name         = "%v"
			url          = "https://mcp.example.com"
			bearer_token = "token-1"
			description  = "Test MCP bearer secret"
			ara_enabled                     = true
			enable_agentic_runtime_authority = true
			enable_ai_quorum                 = true
		}
	`, name, path)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_mcp_secret_bearer_token" "%v" {
			name         = "%v"
			url          = "https://mcp2.example.com"
			bearer_token = "token-2"
			description  = "Updated MCP bearer secret"
			ara_enabled                     = false
			enable_agentic_runtime_authority = false
			enable_ai_quorum                 = false
		}
	`, name, path)

	resourceName := "akeyless_mcp_secret_bearer_token." + name
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ara_enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "enable_agentic_runtime_authority", "true"),
					resource.TestCheckResourceAttr(resourceName, "enable_ai_quorum", "true"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ara_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "enable_agentic_runtime_authority", "false"),
					resource.TestCheckResourceAttr(resourceName, "enable_ai_quorum", "false"),
				),
			},
		},
	})
}

func TestMcpSecretOAuthClientCredsResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "mcp_oauth_cc"
	path := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_mcp_secret_oauth_client_credentials" "%v" {
			name                = "%v"
			url                 = "https://mcp.example.com"
			oauth_client_id     = "client-1"
			oauth_client_secret = "secret-1"
			oauth_token_url     = "https://idp.example.com/token"
			oauth_scopes        = ["read", "write"]
			description         = "Test MCP oauth client credentials"
			ara_enabled                     = true
			enable_agentic_runtime_authority = true
			enable_ai_quorum                 = true
		}
	`, name, path)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_mcp_secret_oauth_client_credentials" "%v" {
			name                = "%v"
			url                 = "https://mcp2.example.com"
			oauth_client_id     = "client-2"
			oauth_client_secret = "secret-2"
			oauth_token_url     = "https://idp2.example.com/token"
			oauth_scopes        = ["admin"]
			description         = "Updated MCP oauth client credentials"
			ara_enabled                     = false
			enable_agentic_runtime_authority = false
			enable_ai_quorum                 = false
		}
	`, name, path)

	resourceName := "akeyless_mcp_secret_oauth_client_credentials." + name
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ara_enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "enable_agentic_runtime_authority", "true"),
					resource.TestCheckResourceAttr(resourceName, "enable_ai_quorum", "true"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ara_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "enable_agentic_runtime_authority", "false"),
					resource.TestCheckResourceAttr(resourceName, "enable_ai_quorum", "false"),
				),
			},
		},
	})
}

func TestMcpSecretOAuthAuthCodeResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "mcp_oauth_ac"
	path := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_mcp_secret_oauth_authorization_code" "%v" {
			name                = "%v"
			url                 = "https://mcp.example.com"
			oauth_client_id     = "client-1"
			oauth_client_secret = "secret-1"
			oauth_token_url     = "https://idp.example.com/token"
			oauth_redirect_uri  = "http://localhost:8080/callback"
			oauth_refresh_token = "refresh-1"
			oauth_scopes        = ["openid"]
			description         = "Test MCP oauth auth code"
			ara_enabled                     = true
			enable_agentic_runtime_authority = true
			enable_ai_quorum                 = true
		}
	`, name, path)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_mcp_secret_oauth_authorization_code" "%v" {
			name                = "%v"
			url                 = "https://mcp2.example.com"
			oauth_client_id     = "client-2"
			oauth_client_secret = "secret-2"
			oauth_token_url     = "https://idp2.example.com/token"
			oauth_redirect_uri  = "http://localhost:8080/callback2"
			oauth_refresh_token = "refresh-2"
			oauth_scopes        = ["openid", "profile"]
			description         = "Updated MCP oauth auth code"
			ara_enabled                     = false
			enable_agentic_runtime_authority = false
			enable_ai_quorum                 = false
		}
	`, name, path)

	resourceName := "akeyless_mcp_secret_oauth_authorization_code." + name
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ara_enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "enable_agentic_runtime_authority", "true"),
					resource.TestCheckResourceAttr(resourceName, "enable_ai_quorum", "true"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "ara_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "enable_agentic_runtime_authority", "false"),
					resource.TestCheckResourceAttr(resourceName, "enable_ai_quorum", "false"),
				),
			},
		},
	})
}
