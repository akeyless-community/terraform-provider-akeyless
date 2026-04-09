package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestDynamicSecretGithubResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	const (
		GITHUB_TOKEN_PERM = `["contents=read", "issues=write", "actions=read"]`
		GITHUB_TOKEN_REPO = `["github-producer-test1", "github-producer-test2"]`
	)

	name := "github_test"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name                      = "%v"
			installation_id           = 1234
			installation_organization = "test"
			token_permissions         = %v
			github_app_id             = 1234
			github_app_private_key    = "test"
			token_ttl                 = "50m"
		}
	`, name, itemPath, GITHUB_TOKEN_PERM)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name                      = "%v"
			installation_id           = "1234"
			installation_repository   = "test"
			installation_organization = "test"
			token_repositories        = %v
			github_app_id             = 1234
			github_app_private_key    = "test"
			token_ttl                 = "40m"
		}
	`, name, itemPath, GITHUB_TOKEN_REPO)

	configUpdate2 := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name                    = "%v"
			installation_repository = "test"
			token_repositories      = %v
			github_app_id           = 1234
			github_app_private_key  = "test"
			token_ttl               = "40m"
		}
	`, name, itemPath, GITHUB_TOKEN_REPO)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate, configUpdate2)
}

func TestDynamicSecretGitlabResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-gitlab"
	targetPath := testPath(targetName)
	targetDetailsType := "gitlab_target_details"

	expect := map[string]any{
		"access_token": "test",
		"url":          "http://127.0.0.1:81",
	}
	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "gitlab_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gitlab" "%v" {
			name            	= "%v"
			target_name         = "%v"
  			gitlab_url          = "http://127.0.0.1:81"
  			gitlab_token_scopes = "api"
  			gitlab_access_type  = "group"
  			group_name          = "mygroup"
  			ttl      			= "10m"
  			gitlab_access_token = "test"
			tags                = ["t1", "t2"]
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gitlab" "%v" {
			name            	= "%v"
			target_name         = "%v"
  			gitlab_url          = "http://127.0.0.1:81"
  			gitlab_token_scopes = "api"
  			gitlab_access_type  = "group"
  			group_name          = "mygroup2"
  			gitlab_access_token = "test"
			tags                = ["t1", "t2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}
