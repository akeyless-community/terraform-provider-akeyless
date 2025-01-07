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

func TestGatewayUpdateRemoteAccess(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

	name := "test-gw-remote-access"

	t.Run("normal", func(t *testing.T) {
		config := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access" "%v" {
			allowed_urls			 = "https://test.com,https://test2.com"
			legacy_ssh_algorithm 	 = "true"
			rdp_target_configuration = "ext_username"
			kexalgs 				 = "curve25519-sha256"
			hide_session_recording 	 = "false"
			keyboard_layout 		 = "en-us-qwerty"
		}
	`, name)

		configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access" "%v" {
			allowed_urls			 = "https://test3.com,https://test4.com"
			legacy_ssh_algorithm 	 = "false"
			ssh_target_configuration = "ext_username"
			hide_session_recording   = "true"
			keyboard_layout 		 = "en-gb-qwerty"
		}
	`, name)

		testGatewayConfigResource(t, config, configUpdate)
	})

	t.Run("with no create", func(t *testing.T) {
		config := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access" "%v" {
		}
	`, name)

		configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access" "%v" {
			allowed_urls			 = "https://test.com,https://test2.com"
			legacy_ssh_algorithm 	 = "true"
			rdp_target_configuration = "ext_username"
			kexalgs 				 = "curve25519-sha256"
			hide_session_recording 	 = "true"
			keyboard_layout 		 = "en-gb-qwerty"
		}
	`, name)

		testGatewayConfigResource(t, config, configUpdate)
	})
}

func TestGatewayUpdateRemoteAccessRdpRecording(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

	name := "test-gw-remote-access-rdp-recording"

	t.Run("normal aws", func(t *testing.T) {
		config := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	      = "true"
			rdp_session_storage 	      = "aws"
			aws_storage_region 		      = "us-west-2"
			aws_storage_bucket_name       = "test-bucket"
			aws_storage_bucket_prefix     = "test-prefix"
			aws_storage_access_key_id     = "test-access-key"
			aws_storage_secret_access_key = "test-secret-key"
		}
	`, name)

		configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	 = "false"
			rdp_session_storage 	 = ""
		}
	`, name)

		testGatewayConfigResource(t, config, configUpdate)
	})

	t.Run("with false in create", func(t *testing.T) {
		config := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	 = "false"
		}
	`, name)

		configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording    	  = "true"
			rdp_session_storage 	      = "aws"
			aws_storage_region 		      = "us-west-2"
			aws_storage_bucket_name       = "test-bucket"
			aws_storage_bucket_prefix     = "test-prefix"
			aws_storage_access_key_id     = "test-access-key"
			aws_storage_secret_access_key = "test-secret-key"
		}
	`, name)

		testGatewayConfigResource(t, config, configUpdate)
	})

	t.Run("normal azure", func(t *testing.T) {
		config := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	     = "true"
			rdp_session_storage 	     = "azure"
			azure_storage_account_name   = "test-account"
			azure_storage_container_name = "test-container"
			azure_storage_client_id      = "test-client-id"
			azure_storage_client_secret  = "test-client-secret"
			azure_storage_tenant_id      = "test-tenant-id"
		}
	`, name)

		configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	     = "true"
			rdp_session_storage 	     = "azure"
			azure_storage_account_name   = "test-account"
			azure_storage_container_name = "test-container"
			azure_storage_client_id      = "test-client-id2"
		}
	`, name)

		testGatewayConfigResource(t, config, configUpdate)
	})

	t.Run("update provider", func(t *testing.T) {
		config := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	      = "true"
			rdp_session_storage           = "aws"
			aws_storage_region 		      = "us-west-2"
			aws_storage_bucket_name       = "test-bucket"
			aws_storage_bucket_prefix     = "test-prefix"
			aws_storage_access_key_id  	  = "test-access-key"
			aws_storage_secret_access_key = "test-secret-key"
		}
	`, name)

		configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording    	 = "true"
			rdp_session_storage 	     = "azure"
			azure_storage_account_name   = "test-account"
			azure_storage_container_name = "test-container"
			azure_storage_client_id      = "test-client-id"
		}
	`, name)

		testGatewayConfigResource(t, config, configUpdate)
	})

	t.Run("local", func(t *testing.T) {
		config := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	 = "true"
			rdp_session_storage 	 = "local"
		}
	`, name)

		configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	 = "false"
			rdp_session_storage 	 = ""
		}
	`, name)

		testGatewayConfigResource(t, config, configUpdate)
	})

	t.Run("update to local", func(t *testing.T) {
		config := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording    	 = "true"
			rdp_session_storage 	     = "azure"
			azure_storage_account_name   = "test-account"
			azure_storage_container_name = "test-container"
			azure_storage_client_id      = "test-client-id"
			azure_storage_client_secret  = "test-client-secret"
			azure_storage_tenant_id      = "test-tenant-id"
		}
	`, name)

		configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	 = "true"
			rdp_session_storage 	 = "local"
		}
	`, name)

		testGatewayConfigResource(t, config, configUpdate)
	})

	t.Run("update from local", func(t *testing.T) {
		config := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	 = "true"
			rdp_session_storage 	 = "local"
		}
	`, name)

		configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	     = "true"
			rdp_session_storage 	     = "azure"
			azure_storage_account_name   = "test-account"
			azure_storage_container_name = "test-container"
			azure_storage_client_id      = "test-client-id"
			azure_storage_client_secret  = "test-client-secret"
			azure_storage_tenant_id      = "test-tenant-id"
		}
	`, name)

		testGatewayConfigResource(t, config, configUpdate)
	})
}
