package akeyless

import (
	"fmt"
	"testing"
)

func TestGithubDynamicSecretResource(t *testing.T) {

	t.Skip("for now the requested values are fictive")

	name := "github_test"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name            		= "%v"
			installation_id 		= "%v"
			token_permissions 	   	= %v
			github_app_id 		  	= %v
			github_app_private_key	= "%v"
		}
	`, name, itemPath, GITHUB_INSTALL_ID, GITHUB_TOKEN_PERM, GITHUB_APP_ID, GITHUB_APP_KEY)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name            		= "%v"
			installation_repository = "%v"
			token_repositories 		= %v
			github_app_id 			= %v
			github_app_private_key 	= "%v"
		}
	`, name, itemPath, GITHUB_INSTALL_REPO, GITHUB_TOKEN_REPO, GITHUB_APP_ID, GITHUB_APP_KEY)

	configUpdate2 := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name            			= "%v"
			installation_organization 	= "%v"
			token_repositories 			= %v
			github_app_id 				= %v
			github_app_private_key 		= "%v"
		}
	`, name, itemPath, GITHUB_INSTALL_ORGANIZATION, GITHUB_TOKEN_REPO, GITHUB_APP_ID, GITHUB_APP_KEY)

	testItemResource(t, itemPath, config, configUpdate, configUpdate2)
}
