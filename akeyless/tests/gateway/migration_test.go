package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestGatewayMigrationAws(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "migration_aws"
	migrationName := testPath(name)

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
	t.Parallel()

	name := "test-migration-azure-kv"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_azure_kv" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/azure"
			azure_kv_name   = "my-test-vault"
			azure_client_id = "00000000-0000-0000-0000-000000000000"
			azure_secret    = "dummy-secret-value"
			azure_tenant_id = "00000000-0000-0000-0000-000000000001"
		}
	`, name, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_azure_kv" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/azure-updated"
			azure_kv_name   = "my-test-vault-2"
			azure_client_id = "00000000-0000-0000-0000-000000000000"
			azure_secret    = "dummy-secret-value-2"
			azure_tenant_id = "00000000-0000-0000-0000-000000000001"
		}
	`, name, name)

	testMigrationResource(t, config, configUpdate)
}

func TestGatewayMigrationGcp(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "test-migration-gcp"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_gcp" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/gcp"
			gcp_key         = "eyJkdW1teSI6ICJ0ZXN0In0="
		}
	`, name, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_gcp" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/gcp-updated"
			gcp_key         = "eyJkdW1teSI6ICJ0ZXN0MiJ9"
		}
	`, name, name)

	testMigrationResource(t, config, configUpdate)
}

func TestGatewayMigrationHashi(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "test-migration-hashi"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_hashi" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/hashi"
			hashi_url       = "https://vault.example.com:8200"
			hashi_token     = "hvs.dummy-token-value"
		}
	`, name, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_hashi" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/hashi-updated"
			hashi_url       = "https://vault2.example.com:8200"
			hashi_token     = "hvs.dummy-token-value-2"
			hashi_json      = "true"
		}
	`, name, name)

	testMigrationResource(t, config, configUpdate)
}

func TestGatewayMigrationK8s(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "test-migration-k8s"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_k8s" "%v" {
			name            = "%v"
			target_location = "terraform-tests/migrations/k8s"
			k8s_url         = "https://k8s-api.example.com:6443"
			k8s_token       = "eyJhbGciOiJSUzI1NiIsImR1bW15IjoidGVzdCJ9"
			k8s_namespace   = "default"
			k8s_skip_system = true
		}
	`, name, name)

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
	`, name, name)

	testMigrationResource(t, config, configUpdate)
}

func TestGatewayMigrationCertificate(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "migration_cert"
	migrationName := testPath(name)

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
	t.Parallel()

	name := "test-migration-ad"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_active_directory" "%v" {
			name                = "%v"
			target_location     = "terraform-tests/migrations/ad"
			ad_domain_name      = "example.com"
			ad_target_name      = "dummy-ad-target"
			ad_user_base_dn     = "OU=Users,DC=example,DC=com"
			ad_computer_base_dn = "OU=Computers,DC=example,DC=com"
			ad_discovery_types  = ["domain-users", "computers"]
			ad_targets_type     = "ssh"
			ad_ssh_port         = "22"
		}
	`, name, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_active_directory" "%v" {
			name                = "%v"
			target_location     = "terraform-tests/migrations/ad-updated"
			ad_domain_name      = "example.com"
			ad_target_name      = "dummy-ad-target"
			ad_user_base_dn     = "OU=Users,DC=example,DC=com"
			ad_computer_base_dn = "OU=Computers,DC=example,DC=com"
			ad_discovery_types  = ["domain-users", "computers", "local-users"]
			ad_targets_type     = "windows"
			ad_winrm_port       = "5986"
			ad_auto_rotate      = "true"
			ad_rotation_interval = 7
			ad_rotation_hour     = 3
		}
	`, name, name)

	testMigrationResource(t, config, configUpdate)
}

func TestGatewayMigrationServerInventory(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "test-migration-si"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_migration_server_inventory" "%v" {
			name                   = "%v"
			target_location        = "terraform-tests/migrations/si"
			hosts                  = "192.168.1.0/24"
			si_target_name         = "dummy-ssh-target"
			si_users_path_template = "terraform-tests/migrations/si/Users/{COMPUTER_NAME}/{USERNAME}"
		}
	`, name, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_migration_server_inventory" "%v" {
			name                   = "%v"
			target_location        = "terraform-tests/migrations/si-updated"
			hosts                  = "192.168.1.0/24,10.0.0.0/16"
			si_target_name         = "dummy-ssh-target"
			si_users_path_template = "terraform-tests/migrations/si/Users/{COMPUTER_NAME}/{USERNAME}"
			si_auto_rotate         = "true"
			si_rotation_interval   = 30
			si_rotation_hour       = 2
			si_sra_enable_rdp      = "true"
		}
	`, name, name)

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
