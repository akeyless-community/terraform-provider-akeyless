package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestRotatedSecretAwsResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-aws"
	targetPath := testPath(targetName)
	targetDetailsType := "aws_target_details"

	expect := map[string]any{
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
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath, AWS_ACCESS_KEY_ID1, AWS_SECRET_ACCESS_KEY1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_aws" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "api-key"
			authentication_credentials 	= "use-target-creds"
			api_id 						= "%v"
			api_key 					= "%v"
			grace_rotation 				= "true"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath, AWS_ACCESS_KEY_ID1, AWS_SECRET_ACCESS_KEY1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretAzureResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-azure"
	targetPath := testPath(targetName)
	targetDetailsType := "azure_target_details"

	expect := map[string]any{
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
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath, AZURE_USERNAME1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_azure" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			username 					= "%v"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath, AZURE_USERNAME1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func testRotatedSecretAzureApiKey(t *testing.T, targetPath string) {

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
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath, AZURE_CLIENT_ID1, AZURE_CLIENT_SECRET1, AZURE_APP_ID1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_azure" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "api-key"
			authentication_credentials 	= "use-target-creds"
			api_id 						= "%v"
			api_key 					= "%v"
			app_id 						= "%v"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath, AZURE_CLIENT_ID1, AZURE_CLIENT_SECRET1, AZURE_APP_ID1)

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
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_azure" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "azure-storage-account"
			authentication_credentials 	= "use-target-creds"
			storage_account_key_name 	= "kerb2"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretCustomResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-custom"
	targetPath := testPath(targetName)
	targetDetailsType := "web_target_details"

	expect := map[string]any{
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
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_custom" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			custom_payload 				= "payload2"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretDockerhubResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-dockerhub"
	targetPath := testPath(targetName)
	targetDetailsType := "dockerhub_target_details"

	expect := map[string]any{
		"username": "test-user",
		"password": "test-password",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-dockerhub"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_dockerhub" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_dockerhub" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretGcpResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-gcp"
	targetPath := testPath(targetName)
	targetDetailsType := "gcp_target_details"

	expect := map[string]any{
		"gcp_service_account_key": GCP_ROTATOR_KEY1,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	t.Run("service-account-rotator", func(t *testing.T) {
		testRotatedSecretGcpServiceAccount(t, targetPath)
	})

	t.Run("target", func(t *testing.T) {
		testRotatedSecretGcpTarget(t, targetPath)
	})
}

func testRotatedSecretGcpServiceAccount(t *testing.T, targetPath string) {

	rsName := "test-rs-gcp-service-account"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_gcp" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "service-account-rotator"
			authentication_credentials 	= "use-target-creds"
			gcp_key 					= "%v"
			gcp_service_account_email 	= "%v"
		}
	`, rsName, rsPath, targetPath, GCP_ROTATOR_KEY1, GCP_SA_ROTATOR_EMAIL1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_gcp" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "service-account-rotator"
			authentication_credentials 	= "use-target-creds"
			gcp_key 					= "%v"
		}
	`, rsName, rsPath, targetPath, GCP_ROTATOR_KEY1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func testRotatedSecretGcpTarget(t *testing.T, targetPath string) {

	rsName := "test-rs-gcp-target"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_gcp" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			gcp_service_account_email 	= "%v"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath, GCP_SA_ROTATOR_EMAIL1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_gcp" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			gcp_service_account_email 	= "%v"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath, GCP_SA_ROTATOR_EMAIL1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretHanadbResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-hanadb"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "hanadb",
		"host":      "hana-db.example.com",
		"port":      "30015",
		"user_name": "SYSTEM",
		"pwd":       "DummyPass123",
		"db_name":   "SYSTEMDB",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-hanadb"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_hanadb" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_hanadb" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretLdapResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-ldap"
	targetPath := testPath(targetName)
	targetDetailsType := "ldap_target_details"

	expect := map[string]any{
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
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

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
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretMysqlResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-db"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
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
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath, MYSQL_USERNAME1, MYSQL_PASSWORD1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mysql" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "%v"
  			rotated_password 			= "%v"
			password_length 			= "9"
			tags 						= ["t1","t3"]
		}
	`, rsName, rsPath, targetPath, MYSQL_USERNAME1, MYSQL_PASSWORD1)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretOracleResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-oracle"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":      "oracle",
		"host":         "oracle-db.example.com",
		"port":         "1521",
		"user_name":    "admin",
		"pwd":          "DummyPass123",
		"service_name": "ORCL",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-oracle"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_oracle" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_oracle" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretPostgresqlResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-postgresql"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "postgres",
		"host":      "postgresql-db.example.com",
		"port":      "5432",
		"user_name": "admin",
		"pwd":       "DummyPass123",
		"db_name":   "testdb",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-postgresql"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_postgresql" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_postgresql" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretRedisResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-redis"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "redis",
		"host":      "redis-db.example.com",
		"port":      "6379",
		"user_name": "user1",
		"pwd":       "DummyPass123",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-redis"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_redis" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_redis" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretRedshiftResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-redshift"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "redshift",
		"host":      "redshift-cluster.example.com",
		"port":      "5439",
		"user_name": "admin",
		"pwd":       "DummyPass123",
		"db_name":   "dev",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-redshift"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_redshift" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_redshift" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretSnowflakeResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-snowflake"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":           "snowflake",
		"host":              "test-account.snowflakecomputing.com",
		"port":              "443",
		"user_name":         "admin",
		"pwd":               "DummyPass123",
		"db_name":           "TESTDB",
		"snowflake_account": "test-account",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-snowflake"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_snowflake" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_snowflake" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretSshResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-ssh"
	targetPath := testPath(targetName)
	targetDetailsType := "ssh_target_details"

	expect := map[string]any{
		"host":     "ssh.example.com",
		"port":     "22",
		"username": "admin",
		"password": "DummyPass123",
	}
	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-ssh"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_ssh" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_ssh" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretWindowsResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-windows"
	targetPath := testPath(targetName)
	targetDetailsType := "windows_target_details"

	expect := map[string]any{
		"hostname": "windows.example.com",
		"username": "administrator",
		"password": "DummyPass123",
	}
	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-windows"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_windows" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_windows" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}
