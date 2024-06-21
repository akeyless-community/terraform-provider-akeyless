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

func TestGatewayUpdateCache(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

	name := "test-gw-cache"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_cache" "%v" {
			enable_cache        	= "true"
			stale_timeout 			= "50"
			enable_proactive   		= "true"
			minimum_fetch_interval 	= "6"
			backup_interval 		= "2"
		}
	`, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_cache" "%v" {
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateDefaults(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

	keyName := "/protection-key-for-gw-defaults"
	createProtectionKey(t, keyName)
	defer deleteItem(t, keyName)

	name := "test-gw-defaults"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_defaults" "%v" {
			saml_access_id        	= "p-saml-1"
			oidc_access_id 			= "p-oidc-1"
			cert_access_id   		= "p-cert-1"
			key 					= "%s"
			event_on_status_change 	= "true"
		}
	`, name, keyName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_defaults" "%v" {
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}
