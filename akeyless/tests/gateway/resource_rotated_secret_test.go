package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestRotatedSecretAwsResource(t *testing.T) {

	targetName := "test-target-aws"
	targetPath := testPath(targetName)
	targetDetailsType := "aws_target_details"

	expect := map[string]interface{}{
		"access_key_id": AWS_ACCESS_KEY_ID1,
		"access_key":    AWS_SECRET_ACCESS_KEY1,
		"region":        "us-east-2",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-aws"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_aws" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "api-key"
			authentication_credentials 	= "use-target-creds"
			api_id 						= "%v"
			api_key 					= "%v"
			grace_rotation 				= "true"
			key 						= "%v"
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath, AWS_ACCESS_KEY_ID1, AWS_SECRET_ACCESS_KEY1, KEY1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_aws" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "api-key"
			authentication_credentials 	= "use-target-creds"
			api_id 						= "%v"
			api_key 					= "%v"
			grace_rotation 				= "true"
			key 						= "%v"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath, AWS_ACCESS_KEY_ID1, AWS_SECRET_ACCESS_KEY1, KEY1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretAzureResource(t *testing.T) {

	targetName := "test-target-azure"
	targetPath := testPath(targetName)
	targetDetailsType := "azure_target_details"

	expect := map[string]interface{}{
		"client_id":     AZURE_CLIENT_ID1,
		"tenant_id":     AZURE_TENANT_ID1,
		"client_secret": AZURE_CLIENT_SECRET1,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	t.Run("password", func(t *testing.T) {
		testRotatedSecretAzurePassword(t, targetPath)
	})

	t.Run("api_key", func(t *testing.T) {
		testRotatedSecretAzureApiKey(t, targetPath)
	})

	t.Run("storage_account", func(t *testing.T) {
		testRotatedSecretAzureStorageAccount(t, targetPath)
	})
}

func testRotatedSecretAzurePassword(t *testing.T, targetPath string) {
	rsName := "test-rs-azure-password"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_azure" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			username 					= "%v"
			key 						= "%v"
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath, AZURE_USERNAME1, KEY1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_azure" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			username 					= "%v"
			key 						= "%v"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath, AZURE_USERNAME1, KEY1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func testRotatedSecretAzureApiKey(t *testing.T, targetPath string) {

	t.Skip("app_id is not real")

	rsName := "test-rs-azure-api-key"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_azure" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "api-key"
			authentication_credentials 	= "use-target-creds"
			api_id 						= "%v"
			api_key 					= "%v"
			app_id 						= "%v"
			key 						= "%v"
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath, AZURE_CLIENT_ID1, AZURE_CLIENT_SECRET1, AZURE_APP_ID1, KEY1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_azure" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "api-key"
			authentication_credentials 	= "use-target-creds"
			api_id 						= "%v"
			api_key 					= "%v"
			app_id 						= "%v"
			key 						= "%v"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath, AZURE_CLIENT_ID1, AZURE_CLIENT_SECRET1, AZURE_APP_ID1, KEY1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func testRotatedSecretAzureStorageAccount(t *testing.T, targetPath string) {
	rsName := "test-rs-azure-storage-account"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_azure" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "azure-storage-account"
			authentication_credentials 	= "use-target-creds"
			storage_account_key_name 	= "key1"
			key 						= "%v"
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath, KEY1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_azure" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "azure-storage-account"
			authentication_credentials 	= "use-target-creds"
			storage_account_key_name 	= "kerb2"
			key 						= "%v"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath, KEY1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretCustomResource(t *testing.T) {

	targetName := "test-target-custom"
	targetPath := testPath(targetName)
	targetDetailsType := "web_target_details"

	expect := map[string]interface{}{
		"url": "http://127.0.0.1:51790/sync/rotate",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-custom"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_custom" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			custom_payload 				= "payload1"
			key 						= "%v"
		}
	`, rsName, rsPath, targetPath, KEY1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_custom" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			custom_payload 				= "payload2"
			key 						= "%v"
		}
	`, rsName, rsPath, targetPath, KEY1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretGcpResource(t *testing.T) {

	targetName := "test-target-gcp"
	targetPath := testPath(targetName)
	targetDetailsType := "gcp_target_details"

	expect := map[string]interface{}{
		"gcp_service_account_key": GCP_ROTATOR_KEY1,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-gcp"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_gcp" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "service-account-rotator"
			authentication_credentials 	= "use-target-creds"
			gcp_key 					= "%v"
			gcp_service_account_email 	= "%v"
			key 						= "%v"
		}
	`, rsName, rsPath, targetPath, GCP_ROTATOR_KEY1, GCP_SA_ROTATOR_EMAIL1, KEY1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_gcp" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "service-account-rotator"
			authentication_credentials 	= "use-target-creds"
			gcp_key 					= "%v"
			key 						= "%v"
		}
	`, rsName, rsPath, targetPath, GCP_ROTATOR_KEY1, KEY1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretGcpTargetResource(t *testing.T) {

	targetName := "test-target-gcp-target"
	targetPath := testPath(targetName)
	targetDetailsType := "gcp_target_details"

	expect := map[string]interface{}{
		"gcp_service_account_key": GCP_ROTATOR_KEY1,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-gcp-target"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_gcp" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			gcp_service_account_email 	= "%v"
			key 						= "%v"
		}
	`, rsName, rsPath, targetPath, GCP_SA_ROTATOR_EMAIL1, KEY1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_gcp" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			gcp_service_account_email 	= "%v"
			key 						= "%v"
		}
	`, rsName, rsPath, targetPath, GCP_SA_ROTATOR_EMAIL1, KEY1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretLdapResource(t *testing.T) {

	targetName := "test-target-ldap"
	targetPath := testPath(targetName)
	targetDetailsType := "ldap_target_details"

	expect := map[string]interface{}{
		"url":                 "ldap://planetexpress.com:10389",
		"certificate":         "aaaa",
		"bind_dn":             "cn=admin,dc=planetexpress,dc=com",
		"bind_password":       LDAP_PASS,
		"implementation_type": "OpenLDAP",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-ldap"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_ldap" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "ldap"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user1"
			rotated_password 			= "pass1"
			user_dn 					= "dn1"
			user_attribute 				= "attr1"
			key 						= "%v"
		}
	`, rsName, rsPath, targetPath, KEY1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_ldap" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "ldap"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user2"
			rotated_password 			= "pass2"
			user_dn 					= "dn2"
			user_attribute 				= "attr2"
			key 						= "%v"
		}
	`, rsName, rsPath, targetPath, KEY1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretMysqlResource(t *testing.T) {

	targetName := "test-target-db"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]interface{}{
		"user_name": MYSQL_USERNAME1,
		"pwd":       MYSQL_PASSWORD1,
		"host":      MYSQL_HOST1,
		"port":      MYSQL_PORT1,
		"db_name":   MYSQL_DBNAME1,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	rsName := "rotate_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mysql" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "%v"
  			rotated_password 			= "%v"
			password_length 			= "9"
			key 						= "%v"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath, MYSQL_USERNAME1, MYSQL_PASSWORD1, KEY1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mysql" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "%v"
  			rotated_password 			= "%v"
			password_length 			= "9"
			key 						= "%v"
			tags 						= ["t1","t3"]
		}
	`, rsName, rsPath, targetPath, MYSQL_USERNAME1, MYSQL_PASSWORD1, KEY1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}
