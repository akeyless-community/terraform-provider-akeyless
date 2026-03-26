package akeyless

import (
	"fmt"
	"testing"
)

const GITLAB_TOKEN = "XXXXXXXX"

func TestGitlabProducerResource(t *testing.T) {
	skipIfNoGateway(t)
	t.Parallel()

	name := "gitlab_test"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_target_gitlab" "gitlab_test" {
			name 				= "%v"
  			gitlab_access_token = "%v"
  			gitlab_url 			= "http://127.0.0.1:81"
  			description 		= "example"
		}
		resource "akeyless_dynamic_secret_gitlab" "%v" {
			name            	= "%v"
			target_name         = "gitlab_target"
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
	`, t.Name(), GITLAB_TOKEN, name, itemPath, GITLAB_TOKEN)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gitlab" "%v" {
			name            	= "%v"
			target_name         = "gitlab_target"
  			gitlab_url          = "http://127.0.0.1:81"
  			gitlab_token_scopes = "api"
  			gitlab_access_type  = "group"
  			group_name          = "mygroup2"
  			gitlab_access_token = "%v"
		}
	`, name, itemPath, GITLAB_TOKEN)

	testItemResource(t, itemPath, config, configUpdate)
}
