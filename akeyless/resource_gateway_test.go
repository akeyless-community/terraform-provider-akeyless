package akeyless

import (
	"fmt"
	"testing"
)

func TestGatewayAllowedAccess(t *testing.T) {
	t.Parallel()

	name := "test_gw_allowed_access"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_allowed_access" "%v" {
 			name        = "%v"
			description = "description one"
  			access_id   = "p-1rs0cnnmjocu"
  			sub_claims  = {
    			"email" = "test.a@email.com,test.b@email.com"
  			}
  			permissions = "defaults,automatic_migration,dynamic_secret,k8s_auth,event_forwarding,general"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_allowed_access" "%v" {
 			name        = "%v"
			description = "description two"
  			access_id   = "p-1rs0cnnmjocu"
  			sub_claims  = {
    			"email" = "test.a@email.com,test.b@email.com,,test.b@email.com"
  			}
  			permissions = "defaults,automatic_migration,dynamic_secret,k8s_auth,log_forwarding,zero_knowledge_encryption,rotated_secret,caching,event_forwarding,general"
		}
	`, name, itemPath)

	testGatewayAllowedAccessResource(t, config, configUpdate, itemPath)
}
