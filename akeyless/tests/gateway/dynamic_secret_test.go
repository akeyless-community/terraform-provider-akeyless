package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

const (
	GITHUB_INSTALL_ID           = 1234
	GITHUB_INSTALL_ORGANIZATION = "XXXXXXXX"
	GITHUB_INSTALL_REPO         = "XXXXXXXX"
	GITHUB_APP_ID               = 1234
	GITHUB_APP_KEY              = "XXXXXXXX"
	GITLAB_TOKEN                = "XXXXXXXX"
)

var (
	GITHUB_TOKEN_PERM = `["contents=read", "issues=write", "actions=read"]`
	GITHUB_TOKEN_REPO = `["github-producer-test1", "github-producer-test2"]`
)

func TestGithubDynamicSecretResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "github_test"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name            		= "%v"
			installation_id 		= "%v"
			token_permissions 	   	= %v
			github_app_id 		  	= %v
			github_app_private_key	= "%v"
			token_ttl				= "50m"
		}
	`, name, itemPath, GITHUB_INSTALL_ID, GITHUB_TOKEN_PERM, GITHUB_APP_ID, GITHUB_APP_KEY)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name            		= "%v"
			installation_repository = "%v"
			token_repositories 		= %v
			github_app_id 			= %v
			github_app_private_key 	= "%v"
			token_ttl				= "40m"
		}
	`, name, itemPath, GITHUB_INSTALL_REPO, GITHUB_TOKEN_REPO, GITHUB_APP_ID, GITHUB_APP_KEY)

	configUpdate2 := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name            			= "%v"
			installation_organization 	= "%v"
			token_repositories 			= %v
			github_app_id 				= %v
			github_app_private_key 		= "%v"
			token_ttl					= "40m"
		}
	`, name, itemPath, GITHUB_INSTALL_ORGANIZATION, GITHUB_TOKEN_REPO, GITHUB_APP_ID, GITHUB_APP_KEY)

	configUpdate3 := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name            			= "%v"
			installation_id 			= "%v"
			installation_organization 	= "%v"
			token_repositories 			= %v
			github_app_id 				= %v
			github_app_private_key 		= "%v"
			token_ttl					= "40m"
		}
	`, name, itemPath, GITHUB_INSTALL_ID, GITHUB_INSTALL_ORGANIZATION, GITHUB_TOKEN_REPO, GITHUB_APP_ID, GITHUB_APP_KEY)

	configUpdate4 := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name            			= "%v"
			installation_id 			= "%v"
			installation_repository 	= "%v"
			installation_organization 	= "%v"
			token_repositories 			= %v
			github_app_id 				= %v
			github_app_private_key 		= "%v"
			token_ttl					= "40m"
		}
	`, name, itemPath, GITHUB_INSTALL_ID, GITHUB_INSTALL_REPO, GITHUB_INSTALL_ORGANIZATION, GITHUB_TOKEN_REPO, GITHUB_APP_ID, GITHUB_APP_KEY)

	configUpdate5 := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name            			= "%v"
			installation_repository 	= "%v"
			token_repositories 			= %v
			github_app_id 				= %v
			github_app_private_key 		= "%v"
			token_ttl					= "40m"
		}
	`, name, itemPath, GITHUB_INSTALL_REPO, GITHUB_TOKEN_REPO, GITHUB_APP_ID, GITHUB_APP_KEY)

	configUpdate6 := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name            			= "%v"
			installation_id 			= "%v"
			installation_repository 	= "%v"
			installation_organization 	= "%v"
			token_repositories 			= %v
			github_app_id 				= %v
			github_app_private_key 		= "%v"
			token_ttl					= "40m"
		}
	`, name, itemPath, GITHUB_INSTALL_ID, GITHUB_INSTALL_REPO, GITHUB_INSTALL_ORGANIZATION, GITHUB_TOKEN_REPO, GITHUB_APP_ID, GITHUB_APP_KEY)

	configUpdate7 := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name            			= "%v"
			installation_id 			= "%v"
			token_repositories 			= %v
			github_app_id 				= %v
			github_app_private_key 		= "%v"
		}
	`, name, itemPath, GITHUB_INSTALL_ID, GITHUB_TOKEN_REPO, GITHUB_APP_ID, GITHUB_APP_KEY)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate, configUpdate2, configUpdate3, configUpdate4, configUpdate5, configUpdate6, configUpdate7)
}

func TestGitlabProducerResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "gitlab_test"
	itemPath := testPath(name)
	targetPath := testPath("gitlab_target")
	config := fmt.Sprintf(`
		resource "akeyless_target_gitlab" "gitlab_test" {
			name 				= "%v"
  			gitlab_access_token = "%v"
  			gitlab_url 			= "http://127.0.0.1:81"
  			description 		= "example"
		}
		resource "akeyless_dynamic_secret_gitlab" "%v" {
			name            	= "%v"
			target_name         = "%v"
  			gitlab_url          = "http://127.0.0.1:81"
  			gitlab_token_scopes = "api"
  			gitlab_access_type  = "group"
  			group_name          = "mygroup"
  			ttl      			= "10m"
  			gitlab_access_token = "%v"
			depends_on = [
    			akeyless_target_gitlab.gitlab_test,
  			]
		}
	`, targetPath, GITLAB_TOKEN, name, itemPath, targetPath, GITLAB_TOKEN)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_gitlab" "gitlab_test" {
			name 				= "%v"
  			gitlab_access_token = "%v"
  			gitlab_url 			= "http://127.0.0.1:81"
  			description 		= "example"
		}
		resource "akeyless_dynamic_secret_gitlab" "%v" {
			name            	= "%v"
			target_name         = "%v"
  			gitlab_url          = "http://127.0.0.1:81"
  			gitlab_token_scopes = "api"
  			gitlab_access_type  = "group"
  			group_name          = "mygroup2"
  			gitlab_access_token = "%v"
			depends_on = [
    			akeyless_target_gitlab.gitlab_test,
  			]
		}
	`, targetPath, GITLAB_TOKEN, name, itemPath, targetPath, GITLAB_TOKEN)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}
