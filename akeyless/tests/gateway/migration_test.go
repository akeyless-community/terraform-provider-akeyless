package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestGatewayMigrationAws(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	name := "migration_aws"
	migrationName := fmt.Sprintf("tf-test-%s-%s", testRunID, name)

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_aws" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/aws"
			aws_key_id      = "test"
			aws_key         = "test"
			aws_region      = "us-east-1"
		}
	`, name, migrationName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_aws" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/aws-updated"
			aws_key_id      = "test"
			aws_key         = "test"
			aws_region      = "eu-west-1"
		}
	`, name, migrationName)

	testMigrationResource(t, config, configUpdate)
}

func TestGatewayMigrationAzureKv(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	name := "migration_azure_kv"
	migrationName := fmt.Sprintf("tf-test-%s-%s", testRunID, name)

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_azure_kv" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/azure"
			azure_kv_name   = "my-test-vault"
			azure_client_id = "00000000-0000-0000-0000-000000000000"
			azure_secret    = "dummy-secret-value"
			azure_tenant_id = "00000000-0000-0000-0000-000000000001"
		}
	`, name, migrationName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_azure_kv" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/azure-updated"
			azure_kv_name   = "my-test-vault-2"
			azure_client_id = "00000000-0000-0000-0000-000000000000"
			azure_secret    = "dummy-secret-value-2"
			azure_tenant_id = "00000000-0000-0000-0000-000000000001"
		}
	`, name, migrationName)

	testMigrationResource(t, config, configUpdate)
}

func TestGatewayMigrationGcp(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	name := "migration_gcp"
	migrationName := fmt.Sprintf("tf-test-%s-%s", testRunID, name)

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_gcp" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/gcp"
			gcp_key         = "eyJkdW1teSI6ICJ0ZXN0In0="
		}
	`, name, migrationName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_gcp" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/gcp-updated"
			gcp_key         = "eyJkdW1teSI6ICJ0ZXN0MiJ9"
		}
	`, name, migrationName)

	testMigrationResource(t, config, configUpdate)
}

func TestGatewayMigrationHashi(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	name := "migration_hashi"
	migrationName := fmt.Sprintf("tf-test-%s-%s", testRunID, name)

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_hashi" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/hashi"
			hashi_url       = "https://vault.example.com:8200"
			hashi_token     = "hvs.dummy-token-value"
		}
	`, name, migrationName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_hashi" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/hashi-updated"
			hashi_url       = "https://vault2.example.com:8200"
			hashi_token     = "hvs.dummy-token-value-2"
			hashi_json      = "true"
		}
	`, name, migrationName)

	testMigrationResource(t, config, configUpdate)
}

func TestGatewayMigrationK8s(t *testing.T) {

	t.Skip("TODO: GW is broken. Next release will fix this.")

	testutils.SkipIfNoGateway(t)

	name := "migration_k8s"
	migrationName := fmt.Sprintf("tf-test-%s-%s", testRunID, name)

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_k8s" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/k8s"
			k8s_url         = "https://k8s-api.example.com:6443"
			k8s_token       = "eyJhbGciOiJSUzI1NiIsImR1bW15IjoidGVzdCJ9"
			k8s_namespace   = "default"
			k8s_skip_system = true
		}
	`, name, migrationName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_k8s" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/k8s-updated"
			k8s_url         = "https://k8s-api.example.com:6443"
			k8s_username    = "admin"
			k8s_password    = "dummy-password"
			k8s_namespace   = "production"
			k8s_skip_system = false
		}
	`, name, migrationName)

	testMigrationResource(t, config, configUpdate)
}

func TestGatewayMigrationCertificate(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	name := "migration_cert"
	migrationName := fmt.Sprintf("tf-test-%s-%s", testRunID, name)

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_certificate" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/cert"
			hosts           = "192.168.1.0/24,10.0.0.1"
			port_ranges     = "443,8443"
		}
	`, name, migrationName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_certificate" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/cert-updated"
			hosts           = "192.168.1.0/24,10.0.0.1,10.0.0.2"
			port_ranges     = "443,8443,8080-8090"
		}
	`, name, migrationName)

	testMigrationResource(t, config, configUpdate)
}

func TestGatewayMigrationActiveDirectory(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := testPath("ad-ldap-target")
	testutils.CreateLdapTarget(t, targetName, map[string]any{
		"url":           "ldap://dummy-ldap:389",
		"bind_dn":       "CN=admin,DC=example,DC=com",
		"bind_password": "dummy-password",
	})
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetName)
	})

	name := "migration_ad"
	migrationName := fmt.Sprintf("tf-test-%s-%s", testRunID, name)

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_active_directory" "%v" {
			name                = "%v"
			target_location     = "terraform-tests/migrations/ad"
			ad_domain_name      = "example.com"
			ad_target_name      = "%v"
			ad_user_base_dn     = "OU=Users,DC=example,DC=com"
			ad_computer_base_dn = "OU=Computers,DC=example,DC=com"
			ad_discovery_types  = ["domain-users", "computers", "local-users"]
			ad_local_users_path_template = "terraform-tests/migrations/ad/Users/create/{{LOCAL_USER_NAME}}/{{USERNAME}}"
			ad_domain_users_path_template = "terraform-tests/migrations/ad/Users/create/{{DOMAIN_USER_NAME}}/{{USERNAME}}"
			ad_targets_path_template = "terraform-tests/migrations/ad/Targets/create/{{COMPUTER_NAME}}/{{USERNAME}}"
			ad_targets_type     = "ssh"
			ad_ssh_port         = "22"
		}
	`, name, migrationName, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_active_directory" "%v" {
			name                = "%v"
			target_location     = "terraform-tests/migrations/ad-updated"
			ad_domain_name      = "example.com"
			ad_target_name      = "%v"
			ad_user_base_dn     = "OU=Users,DC=example,DC=com"
			ad_computer_base_dn = "OU=Computers,DC=example,DC=com"
			ad_discovery_types  = ["domain-users", "computers", "local-users"]
			ad_local_users_path_template = "terraform-tests/migrations/ad/Users/update/{{LOCAL_USER_NAME}}/{{USERNAME}}"
			ad_domain_users_path_template = "terraform-tests/migrations/ad/Users/update/{{DOMAIN_USER_NAME}}/{{USERNAME}}"
			ad_targets_path_template = "terraform-tests/migrations/ad/Targets/update/{{COMPUTER_NAME}}/{{USERNAME}}"
			ad_targets_type     = "windows"
			ad_winrm_port       = "5986"
			ad_auto_rotate      = "true"
			ad_rotation_interval = 7
			ad_rotation_hour     = 3
		}
	`, name, migrationName, targetName)

	testMigrationResource(t, config, configUpdate)
}

func TestGatewayMigrationServerInventory(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	name := "migration_si"
	migrationName := fmt.Sprintf("tf-test-%s-%s", testRunID, name)

	targetName := testPath("si-ssh-target")
	testutils.CreateSshTarget(t, targetName, map[string]any{
		"username": "dummy",
		"password": "dummy",
		"host":     "127.0.0.1",
		"port":     "22",
	})
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetName)
	})

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_server_inventory" "%v" {
			name                   = "%v"
			target_location        = "terraform-tests/migrations/si"
			hosts                  = "192.168.1.0/24"
			si_target_name         = "%v"
			si_users_path_template = "terraform-tests/migrations/si/Users/{{COMPUTER_NAME}}/{{USERNAME}}"
		}
	`, name, migrationName, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_server_inventory" "%v" {
			name                   = "%v"
			target_location        = "terraform-tests/migrations/si-updated"
			hosts                  = "192.168.1.0/24,10.0.0.0/16"
			si_target_name         = "%v"
			si_users_path_template = "terraform-tests/migrations/si/Users/{{COMPUTER_NAME}}/{{USERNAME}}"
			si_auto_rotate         = "true"
			si_rotation_interval   = 30
			si_rotation_hour       = 2
			si_sra_enable_rdp      = "true"
		}
	`, name, migrationName, targetName)

	testMigrationResource(t, config, configUpdate)
}

func testMigrationResource(t *testing.T, configs ...string) {
	steps := make([]resource.TestStep, len(configs))
	for i, config := range configs {
		steps[i] = resource.TestStep{
			Config: config,
		}
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps:             steps,
	})
}
