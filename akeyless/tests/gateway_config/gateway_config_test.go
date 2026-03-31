package gateway_config

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestGatewayAllowedAccess(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "test_gw_allowed_access"
	itemPath := testPath(name)
	amName := "test_gw_allowed_access_am"
	amPath := testPath(amName)
	permissionsOnCreate := "defaults,automatic_migration,dynamic_secret,k8s_auth,event_forwarding,general"
	emailSubClaimsOnCreate := "test.a@email.com,test.b@email.com"

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "%v" {
			name = "%v"
		}

		resource "akeyless_gateway_allowed_access" "%v" {
 			name           = "%v"
			description    = "description one"
  			access_id      = akeyless_auth_method_api_key.%v.access_id
  			case_sensitive = "true"
  			sub_claims     = {
    			"email" = "%v"
  			}
  			permissions = "%v"
		}
	`, amName, amPath, name, itemPath, amName, emailSubClaimsOnCreate, permissionsOnCreate)

	permissionsOnUpdate := "defaults,automatic_migration,dynamic_secret,k8s_auth,log_forwarding,zero_knowledge_encryption,rotated_secret,caching,event_forwarding,general"
	emailSubClaimsOnUpdate := "test.a@email.com,test.b@email.com,test.b@email.com"

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "%v" {
			name = "%v"
		}

		resource "akeyless_gateway_allowed_access" "%v" {
 			name                        = "%v"
			description                 = "description two"
  			access_id                   = akeyless_auth_method_api_key.%v.access_id
  			case_sensitive              = "false"
  			sub_claims_case_insensitive = true
  			sub_claims                  = {
    			"email" = "%v"
  			}
  			permissions = "%v"
		}
	`, amName, amPath, name, itemPath, amName, emailSubClaimsOnUpdate, permissionsOnUpdate)

	inputParams := &testutils.TestGatewayAllowedAccessInput{
		Config:                 config,
		ConfigUpdate:           configUpdate,
		ItemPath:               itemPath,
		PermissionsOnCreate:    permissionsOnCreate,
		PermissionsOnUpdate:    permissionsOnUpdate,
		EmailSubClaimsOnCreate: emailSubClaimsOnCreate,
		EmailSubClaimsOnUpdate: emailSubClaimsOnUpdate,
	}

	testutils.TestGatewayAllowedAccessRunFunc(t, providerFactories, inputParams)
}

func TestGatewayUpdateCache(t *testing.T) {
	testutils.SkipIfNoGateway(t)

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
			enable_cache        	= "false"
			stale_timeout 			= "60"
			enable_proactive   		= "false"
			minimum_fetch_interval 	= "5"
			backup_interval 		= "1"
		}
	`, name)

	testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
}

func TestGatewayUpdateDefaults(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	keyName := "/protection-key-for-gw-defaults"
	testutils.CreateProtectionKey(t, keyName)
	defer testutils.DeleteItem(t, keyName)

	name := "test-gw-defaults"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_defaults" "%v" {
			saml_access_id        	= "p-saml-1"
			oidc_access_id 			= "p-oidc-1"
			cert_access_id   		= "p-cert-1"
			key 					= "%s"
			event_on_status_change 	= "true"
			hvp_route_version 		= 2
		}
	`, name, keyName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_defaults" "%v" {
		}
	`, name)

	testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
}

func TestGatewayUpdateRemoteAccess(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "test-gw-remote-access"

	t.Run("normal", func(t *testing.T) {
		config := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access" "%v" {
			allowed_urls			     = "https://test.com,https://test2.com"
			allowed_ssh_url 		     = "ssh://test.com:22"
			legacy_ssh_algorithm 	     = "true"
			rdp_target_configuration     = "ext_username"
			kexalgs 				     = "curve25519-sha256"
			hide_session_recording 	     = "false"
			keyboard_layout 		     = "en-us-qwerty"
			default_session_ttl_minutes  = "30"
		}
	`, name)

		configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access" "%v" {
			allowed_urls			     = "https://test3.com,https://test4.com"
			allowed_ssh_url 		     = "ssh://test2.com:22"
			legacy_ssh_algorithm 	     = "false"
			ssh_target_configuration     = "ext_username"
			hide_session_recording       = "true"
			keyboard_layout 		     = "en-gb-qwerty"
			default_session_ttl_minutes  = "60"
		}
	`, name)

		testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
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

		testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
	})
}

func TestGatewayUpdateRemoteAccessRdpRecording(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "test-gw-remote-access-rdp-recording"

	t.Run("normal aws", func(t *testing.T) {
		config := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	              = "true"
			rdp_session_storage 	              = "aws"
			aws_storage_region 		              = "us-west-2"
			aws_storage_bucket_name               = "test-bucket"
			aws_storage_bucket_prefix             = "test-prefix"
			aws_storage_access_key_id             = "test-access-key"
			aws_storage_secret_access_key         = "test-secret-key"
			rdp_session_recording_compress         = true
			rdp_session_recording_quality          = "medium"
		}
	`, name)

		configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_remote_access_rdp_recording" "%v" {
			rdp_session_recording 	 = "false"
			rdp_session_storage 	 = ""
		}
	`, name)

		testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
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

		testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
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

		testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
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

		testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
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

		testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
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

		testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
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

		testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
	})
}

func TestK8sAuthConfig(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "test_k8s_auth"

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "k8s_auth_am" {
			name = "%v"
		}
		resource "akeyless_k8s_auth_config" "%v" {
			name                      = "%v"
			access_id                 = akeyless_auth_method_api_key.k8s_auth_am.access_id
			signing_key               = "dGVzdA=="
			k8s_host                  = "https://k8s-api.example.com:6443"
			k8s_ca_cert               = "dGVzdA=="
			token_reviewer_jwt        = "eyJhbGciOiJSUzI1NiIsImR1bW15IjoidGVzdCJ9"
			disable_issuer_validation = "true"
			depends_on = [akeyless_auth_method_api_key.k8s_auth_am]
		}
	`, testPath("k8s_auth_am"), name, testPath(name))

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "k8s_auth_am" {
			name = "%v"
		}
		resource "akeyless_k8s_auth_config" "%v" {
			name                      = "%v"
			access_id                 = akeyless_auth_method_api_key.k8s_auth_am.access_id
			signing_key               = "dGVzdA=="
			k8s_host                  = "https://k8s-api.example.com:6443"
			k8s_ca_cert               = "dGVzdA=="
			token_reviewer_jwt        = "eyJhbGciOiJSUzI1NiIsImR1bW15IjoidGVzdCJ9"
			token_exp                 = 600
			disable_issuer_validation = "true"
			depends_on = [akeyless_auth_method_api_key.k8s_auth_am]
		}
	`, testPath("k8s_auth_am"), name, testPath(name))

	testutils.TestGatewayConfigResource(t, providerFactories, config, configUpdate)
}
