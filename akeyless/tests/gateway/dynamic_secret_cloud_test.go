// generated file
package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestDynamicSecretAws(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_aws_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_aws" "%v" {
			name                 = "%v"
			aws_access_key_id    = "test"
			aws_access_secret_key = "test"
			region               = "us-east-1"
			user_ttl             = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_aws" "%v" {
			name                 = "%v"
			aws_access_key_id    = "test"
			aws_access_secret_key = "test"
			region               = "eu-west-1"
			user_ttl             = "60m"
			tags                 = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretAzure(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_azure_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_azure" "%v" {
			name                = "%v"
			azure_tenant_id     = "00000000-0000-0000-0000-000000000001"
			azure_client_id     = "00000000-0000-0000-0000-000000000002"
			azure_client_secret = "dummy-client-secret"
			user_ttl            = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_azure" "%v" {
			name                = "%v"
			azure_tenant_id     = "00000000-0000-0000-0000-000000000001"
			azure_client_id     = "00000000-0000-0000-0000-000000000002"
			azure_client_secret = "dummy-client-secret-2"
			user_ttl            = "60m"
			tags                = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretGcp(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_gcp_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gcp" "%v" {
			name              = "%v"
			gcp_sa_email      = "test@test.com"
			gcp_key           = "eyJkdW1teSI6ICJ0ZXN0In0="
			service_account_type = "fixed"
			user_ttl          = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gcp" "%v" {
			name              = "%v"
			gcp_sa_email      = "test@test.com"
			gcp_key           = "eyJkdW1teSI6ICJ0ZXN0In0="
			service_account_type = "fixed"
			user_ttl          = "60m"
			tags              = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretEks(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_eks_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_eks" "%v" {
			name                  = "%v"
			eks_access_key_id     = "test"
			eks_secret_access_key = "test"
			eks_region            = "us-east-1"
			eks_cluster_name      = "test-cluster"
			eks_cluster_endpoint  = "https://eks.example.com"
			eks_cluster_ca_cert   = "LS0tLS1CRUdJTi..."
			user_ttl              = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_eks" "%v" {
			name                  = "%v"
			eks_access_key_id     = "test"
			eks_secret_access_key = "test"
			eks_region            = "eu-west-1"
			eks_cluster_name      = "test-cluster"
			eks_cluster_endpoint  = "https://eks.example.com"
			eks_cluster_ca_cert   = "LS0tLS1CRUdJTi..."
			user_ttl              = "60m"
			tags                  = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretGke(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_gke_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gke" "%v" {
			name                      = "%v"
			gke_account_key           = "eyJkdW1teSI6ICJ0ZXN0In0="
			gke_cluster_endpoint      = "https://gke.example.com"
			gke_cluster_cert          = "LS0tLS1CRUdJTi..."
			gke_service_account_email = "test@test.com"
			gke_cluster_name          = "test-cluster"
			user_ttl                  = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gke" "%v" {
			name                      = "%v"
			gke_account_key           = "eyJkdW1teSI6ICJ0ZXN0In0="
			gke_cluster_endpoint      = "https://gke.example.com"
			gke_cluster_cert          = "LS0tLS1CRUdJTi..."
			gke_service_account_email = "test@test.com"
			gke_cluster_name          = "test-cluster"
			user_ttl                  = "60m"
			tags                      = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretK8s(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_k8s_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_k8s" "%v" {
			name                 = "%v"
			k8s_cluster_endpoint = "https://k8s-api.example.com:6443"
			k8s_cluster_ca_cert  = "dGVzdA=="
			k8s_cluster_token    = "eyJhbGciOiJSUzI1NiIsImR1bW15IjoidGVzdCJ9"
			k8s_namespace        = "default"
			user_ttl             = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_k8s" "%v" {
			name                 = "%v"
			k8s_cluster_endpoint = "https://k8s-api.example.com:6443"
			k8s_cluster_ca_cert  = "dGVzdA=="
			k8s_cluster_token    = "eyJhbGciOiJSUzI1NiIsImR1bW15IjoidGVzdCJ9"
			k8s_namespace        = "production"
			user_ttl             = "60m"
			tags                 = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretLdap(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_ldap_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_ldap" "%v" {
			name             = "%v"
			ldap_url         = "ldap://ldap.example.com:389"
			bind_dn          = "cn=admin,dc=example,dc=com"
			bind_dn_password = "DummyPass123"
			user_dn          = "ou=users,dc=example,dc=com"
			user_ttl         = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_ldap" "%v" {
			name             = "%v"
			ldap_url         = "ldap://ldap.example.com:389"
			bind_dn          = "cn=admin,dc=example,dc=com"
			bind_dn_password = "DummyPass123"
			user_dn          = "ou=users,dc=example,dc=com"
			user_ttl         = "60m"
			tags             = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretArtifactory(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_artifactory_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_artifactory" "%v" {
			name                       = "%v"
			artifactory_token_scope    = "member-of-groups:readers"
			artifactory_token_audience = "jfrt@*"
			artifactory_admin_name     = "admin"
			artifactory_admin_pwd      = "DummyPass123"
			base_url                   = "https://artifactory.example.com"
			user_ttl                   = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_artifactory" "%v" {
			name                       = "%v"
			artifactory_token_scope    = "member-of-groups:deployers"
			artifactory_token_audience = "jfrt@*"
			artifactory_admin_name     = "admin"
			artifactory_admin_pwd      = "DummyPass123"
			base_url                   = "https://artifactory.example.com"
			user_ttl                   = "60m"
			tags                       = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretCustom(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_custom_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_custom" "%v" {
			name             = "%v"
			create_sync_url  = "https://webhook.example.com/create"
			revoke_sync_url  = "https://webhook.example.com/revoke"
			user_ttl         = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_custom" "%v" {
			name             = "%v"
			create_sync_url  = "https://webhook.example.com/create"
			revoke_sync_url  = "https://webhook.example.com/revoke"
			user_ttl         = "60m"
			tags             = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretDockerhub(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_dockerhub_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_dockerhub" "%v" {
			name               = "%v"
			dockerhub_username = "dummyuser"
			dockerhub_password = "DummyPass123"
			user_ttl           = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_dockerhub" "%v" {
			name               = "%v"
			dockerhub_username = "dummyuser"
			dockerhub_password = "DummyPass123"
			user_ttl           = "60m"
			tags               = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretOpenai(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "ds_openai_target"
	targetPath := testPath(targetName)
	name := "ds_openai_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name       = "%v"
			api_key    = "sk-dummy-key-1234567890"
			openai_url = "https://api.openai.com"
		}
		resource "akeyless_dynamic_secret_openai" "%v" {
			name        = "%v"
			target_name = "%v"
			project_id  = "proj-dummy-123"
			user_ttl    = "30m"
			depends_on  = [akeyless_target_openai.%v]
		}
	`, targetName, targetPath,
		name, itemPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name       = "%v"
			api_key    = "sk-dummy-key-1234567890"
			openai_url = "https://api.openai.com"
		}
		resource "akeyless_dynamic_secret_openai" "%v" {
			name        = "%v"
			target_name = "%v"
			project_id  = "proj-dummy-123"
			user_ttl    = "60m"
			tags        = ["test1", "test2"]
			depends_on  = [akeyless_target_openai.%v]
		}
	`, targetName, targetPath,
		name, itemPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretPing(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_ping_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_ping" "%v" {
			name                 = "%v"
			ping_url             = "https://example.com"
			ping_privileged_user = "admin"
			ping_password        = "DummyPass123"
			ping_redirect_uris   = ["https://example.com/callback"]
			user_ttl             = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_ping" "%v" {
			name                 = "%v"
			ping_url             = "https://example.com"
			ping_privileged_user = "admin"
			ping_password        = "DummyPass123"
			ping_redirect_uris   = ["https://example.com/callback"]
			user_ttl             = "60m"
			tags                 = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretRdp(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_rdp_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_rdp" "%v" {
			name            = "%v"
			rdp_admin_name  = "administrator"
			rdp_admin_pwd   = "DummyPass123"
			rdp_host_name   = "rdp.example.com"
			rdp_host_port   = "3389"
			rdp_user_groups = "Administrators"
			user_ttl        = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_rdp" "%v" {
			name            = "%v"
			rdp_admin_name  = "administrator"
			rdp_admin_pwd   = "DummyPass123"
			rdp_host_name   = "rdp.example.com"
			rdp_host_port   = "3389"
			rdp_user_groups = "Administrators"
			user_ttl        = "60m"
			tags            = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretSnowflake(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_snowflake_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_snowflake" "%v" {
			name             = "%v"
			account_username = "admin"
			account_password = "DummyPass123"
			account          = "test-account.snowflakecomputing.com"
			db_name          = "TESTDB"
			user_ttl         = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_snowflake" "%v" {
			name             = "%v"
			account_username = "admin"
			account_password = "DummyPass123"
			account          = "test-account.snowflakecomputing.com"
			db_name          = "TESTDB"
			user_ttl         = "60m"
			tags             = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretVenafi(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "ds_venafi_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_venafi" "%v" {
			name            = "%v"
			venafi_api_key  = "dummy-api-key-12345"
			venafi_zone     = "Test\\Policy"
			venafi_baseurl  = "https://venafi.example.com"
			user_ttl        = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_venafi" "%v" {
			name            = "%v"
			venafi_api_key  = "dummy-api-key-12345"
			venafi_zone     = "Test\\Policy"
			venafi_baseurl  = "https://venafi.example.com"
			user_ttl        = "60m"
			tags            = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}
