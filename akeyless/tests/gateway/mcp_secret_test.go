package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
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
		}
	`, name, path)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_mcp_secret_bearer_token" "%v" {
			name         = "%v"
			url          = "https://mcp2.example.com"
			bearer_token = "token-2"
			description  = "Updated MCP bearer secret"
		}
	`, name, path)

	testutils.TestItemResource(t, providerFactories, path, config, configUpdate)
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
		}
	`, name, path)

	testutils.TestItemResource(t, providerFactories, path, config, configUpdate)
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
		}
	`, name, path)

	testutils.TestItemResource(t, providerFactories, path, config, configUpdate)
}
