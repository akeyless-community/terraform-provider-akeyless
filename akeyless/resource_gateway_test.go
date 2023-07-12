package akeyless

import (
	"fmt"
	"testing"
)

func TestGatewayAllowedAccess(t *testing.T) {
	t.Skip("for now the requested values are fictive")
	t.Parallel()

	name := "test_gw_allowed_access"
	itemPath := testPath(name)
	permissionsOnCreate := "defaults,automatic_migration,dynamic_secret,k8s_auth,event_forwarding,general"
	emailSubClaimsOnCreate := "test.a@email.com,test.b@email.com"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_allowed_access" "%v" {
 			name        = "%v"
			description = "description one"
  			access_id   = "p-1rs0cnnmjocu"
  			sub_claims  = {
    			"email" = "%v"
  			}
  			permissions = "%v"
		}
	`, name, itemPath, emailSubClaimsOnCreate, permissionsOnCreate)

	permissionsOnUpdate := "defaults,automatic_migration,dynamic_secret,k8s_auth,log_forwarding,zero_knowledge_encryption,rotated_secret,caching,event_forwarding,general"
	emailSubClaimsOnUpdate := "test.a@email.com,test.b@email.com,test.b@email.com"

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_allowed_access" "%v" {
 			name        = "%v"
			description = "description two"
  			access_id   = "p-1rs0cnnmjocu"
  			sub_claims  = {
    			"email" = "%v"
  			}
  			permissions = "%v"
		}
	`, name, itemPath, emailSubClaimsOnUpdate, permissionsOnUpdate)

	inputParams := &TestGatewayAllowedAccessResource{
		Config:                 config,
		ConfigUpdate:           configUpdate,
		ItemPath:               itemPath,
		PermissionsOnCreate:    permissionsOnCreate,
		PermissionsOnUpdate:    permissionsOnUpdate,
		EmailSubClaimsOnCreate: emailSubClaimsOnCreate,
		emailSubClaimsOnUpdate: emailSubClaimsOnUpdate,
	}

	testGatewayAllowedAccessResource(t, inputParams)
}
