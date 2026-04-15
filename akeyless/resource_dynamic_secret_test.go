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

	testItemResource(t, itemPath, config, configUpdate, configUpdate2, configUpdate3, configUpdate4, configUpdate5, configUpdate6, configUpdate7)
}

func TestAwsDynamicSecretSessionTags(t *testing.T) {

	t.Skip("requires real AWS credentials")

	name := "aws_session_tags_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_aws" "%v" {
			name                = "%v"
			access_mode         = "assume_role"
			aws_role_arns       = "arn:aws:iam::123456789012:role/TestRole"
			session_tags        = "Key=Team,Value=Platform Key=Environment,Value=Dev"
			transitive_tag_keys = "Team"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_aws" "%v" {
			name                = "%v"
			access_mode         = "assume_role"
			aws_role_arns       = "arn:aws:iam::123456789012:role/TestRole"
			session_tags        = "Key=Team,Value=Platform Key=Environment,Value=Staging Key=CostCenter,Value=12345"
			transitive_tag_keys = "Team CostCenter"
		}
	`, name, itemPath)

	testItemResource(t, itemPath, config, configUpdate)
}
