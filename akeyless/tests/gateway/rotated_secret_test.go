package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestRotatedSecretAwsResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-aws"
	targetPath := testPath(targetName)
	targetDetailsType := "aws_target_details"

	expect := map[string]any{
		"access_key_id": "test",
		"access_key":    "test",
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
			api_id 						= "test"
			api_key 					= "test"
			grace_rotation 				= "true"
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_aws" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "api-key"
			authentication_credentials 	= "use-target-creds"
			api_id 						= "test"
			api_key 					= "test"
			grace_rotation 				= "true"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretAzureResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-azure"
	targetPath := testPath(targetName)
	targetDetailsType := "azure_target_details"

	expect := map[string]any{
		"client_id":     "test",
		"tenant_id":     "test",
		"client_secret": "test",
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
			username 					= "test"
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_azure" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			username 					= "test"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath)

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
			api_id 						= "test1"
			api_key 					= "test1"
			app_id 						= "test1"
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_azure" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "api-key"
			authentication_credentials 	= "use-target-creds"
			api_id 						= "test2"
			api_key 					= "test2"
			app_id 						= "test2"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath)

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

func TestRotatedSecretCassandraResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-cassandra"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "cassandra",
		"host":      "cassandra-db.example.com",
		"port":      "9042",
		"db_name":   "testdb",
		"user_name": "admin",
		"pwd":       "DummyPass123",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-cassandra"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_cassandra" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user1"
			rotated_password 			= "pass1"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_cassandra" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user2"
			rotated_password 			= "pass2"
			tags 						= ["t1", "t3"]
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
			password_length 			= "12"
			input_rule 					= ["name=in1,rule=validate input"]
			output_rule 				= ["name=out1,rule=mask output"]
			use_capital_letters 		= "true"
			use_lower_letters 			= "true"
			use_numbers 				= "true"
			use_special_characters 		= "false"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_custom" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			custom_payload 				= "payload2"
			password_length 			= "14"
			input_rule 					= ["name=in1,rule=validate input updated"]
			output_rule 				= ["name=out1,rule=mask output updated"]
			use_capital_letters 		= "true"
			use_lower_letters 			= "true"
			use_numbers 				= "true"
			use_special_characters 		= "true"
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
		"gcp_service_account_key": testutils.GCP_KEY,
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
			gcp_service_account_email 	= "test@test.com"
		}
	`, rsName, rsPath, targetPath, testutils.GCP_KEY)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_gcp" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "service-account-rotator"
			authentication_credentials 	= "use-target-creds"
			gcp_key 					= "%v"
			gcp_service_account_email 	= "test@test.com"
		}
	`, rsName, rsPath, targetPath, testutils.GCP_KEY)

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
			gcp_service_account_email 	= "test@test.com"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_gcp" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			gcp_service_account_email 	= "test@test.com"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

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
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user1"
			rotated_password 			= "pass1"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_hanadb" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user2"
			rotated_password 			= "pass2"
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
		"bind_password":       "test",
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

func TestRotatedSecretMongodbResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-mongodb"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "mongodb",
		"host":      "mongodb-db.example.com",
		"port":      "27017",
		"db_name":   "testdb",
		"user_name": "admin",
		"pwd":       "DummyPass123",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-mongodb"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mongodb" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user1"
			rotated_password 			= "pass1"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mongodb" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user2"
			rotated_password 			= "pass2"
			tags 						= ["t1", "t3"]
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretMssqlResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-mssql"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "mssql",
		"host":      "mssql-db.example.com",
		"port":      "1433",
		"db_name":   "testdb",
		"user_name": "admin",
		"pwd":       "DummyPass123",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-mssql"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mssql" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user1"
			rotated_password 			= "pass1"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mssql" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user2"
			rotated_password 			= "pass2"
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
		"db_type":   "mysql",
		"user_name": "test",
		"pwd":       "test",
		"host":      "127.0.0.1",
		"port":      "3306",
		"db_name":   "test",
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
			rotated_username 			= "test"
  			rotated_password 			= "test"
			password_length 			= "9"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mysql" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "target"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "test"
  			rotated_password 			= "test"
			password_length 			= "9"
			tags 						= ["t1","t3"]
		}
	`, rsName, rsPath, targetPath)

	resourceName := "akeyless_rotated_secret_mysql." + rsName
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckItemExistsRemotely(rsPath),
					resource.TestCheckResourceAttr(resourceName, "password_length", "9"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckItemExistsRemotely(rsPath),
					resource.TestCheckResourceAttr(resourceName, "password_length", "9"),
				),
			},
		},
	})
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
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user1"
			rotated_password 			= "pass1"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_oracle" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			rotated_username 			= "user2"
			rotated_password 			= "pass2"
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
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user1"
			rotated_password 			= "pass1"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_postgresql" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user2"
			rotated_password 			= "pass2"
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
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user1"
			rotated_password 			= "pass1"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_redis" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user2"
			rotated_password 			= "pass2"
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
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user1"
			rotated_password 			= "pass1"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_redshift" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user2"
			rotated_password 			= "pass2"
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
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user1"
			rotated_password 			= "pass1"
			tags 						= ["t1", "t2"]
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_snowflake" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user2"
			rotated_password 			= "pass2"
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

func TestRotatedSecretOpenAIResource(t *testing.T) {

	// TODO: add tags to test after saas deployed.

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-openai"
	targetPath := testPath(targetName)
	targetDetailsType := "openai_target_details"

	expect := map[string]any{
		"api_key": "sk-test-key-12345",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-openai"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_openai" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "api-key"
			authentication_credentials 	= "use-target-creds"
			api_key 					= "sk-test-key-12345"
			api_key_id 					= "key-id-1"
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_openai" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "api-key"
			authentication_credentials 	= "use-target-creds"
			api_key 					= "sk-test-key-12345"
			api_key_id 					= "key-id-2"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretSplunkResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-splunk"
	targetPath := testPath(targetName)
	targetDetailsType := "splunk_target_details"

	expect := map[string]any{
		"url":      "https://splunk.example.com:8089",
		"username": "admin",
		"password": "DummyPass123",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	t.Run("password", func(t *testing.T) {
		testRotatedSecretSplunkPassword(t, targetPath)
	})

	t.Run("token", func(t *testing.T) {
		testRotatedSecretSplunkToken(t, targetPath)
	})

	t.Run("hec_token", func(t *testing.T) {
		testRotatedSecretSplunkHecToken(t, targetPath)
	})
}

func testRotatedSecretSplunkPassword(t *testing.T, targetPath string) {

	t.Skip("TODO: SDK is broken, skipping. Need to add user/pass arguments to update command")

	rsName := "test-rs-splunk-password"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_splunk" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user1"
			rotated_password 			= "pass1"
			splunk_token 				= "dummy-splunk-token-1"
			token_owner 				= "admin"
			audience 					= "test-audience"
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_splunk" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "password"
			authentication_credentials 	= "use-target-creds"
			rotated_username 			= "user1"
			rotated_password 			= "pass1"
			splunk_token 				= "dummy-token-2"
			token_owner 				= "admin"
			audience 					= "test-audience"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func testRotatedSecretSplunkToken(t *testing.T, targetPath string) {

	rsName := "test-rs-splunk-token"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_splunk" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "token-rotator"
			authentication_credentials 	= "use-target-creds"
			splunk_token 				= "dummy-splunk-token-1"
			token_owner 				= "admin"
			audience 					= "test-audience"
			expiration_date 			= "2027-01-01"
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_splunk" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "token-rotator"
			authentication_credentials 	= "use-target-creds"
			splunk_token 				= "dummy-splunk-token-2"
			token_owner 				= "admin"
			audience 					= "test-audience-2"
			expiration_date 			= "2027-06-01"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func testRotatedSecretSplunkHecToken(t *testing.T, targetPath string) {

	rsName := "test-rs-splunk-hec"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_splunk" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "hec-token-rotator"
			authentication_credentials 	= "use-target-creds"
			hec_token 					= "dummy-hec-token-1"
			hec_token_name 				= "my-hec-input"
			description 				= "aaaa"
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_splunk" "%v" {
			name 						= "%v"
			target_name 				= "%v"
			rotator_type 				= "hec-token-rotator"
			authentication_credentials 	= "use-target-creds"
			hec_token 					= "dummy-hec-token-2"
			hec_token_name 				= "my-hec-input"
			description 				= "bbbb"
		}
	`, rsName, rsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretDataSource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-db"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "mysql",
		"user_name": testutils.DockerMysqlUser,
		"pwd":       testutils.DockerMysqlPassword,
		"host":      testutils.DockerMysqlHost,
		"port":      testutils.DockerMysqlPort,
		"db_name":   testutils.DockerMysqlDB,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-for-ds"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_mysql" "%v" {
			name            = "%v"
			target_name     = "%v"
			rotator_type    = "target"
			authentication_credentials 	= "use-target-creds"
		}
		data "akeyless_rotated_secret" "rsv" {
			name       = "%v"
			depends_on = [akeyless_rotated_secret_mysql.%v]
		}
	`, rsName, rsPath, targetPath, rsPath, rsName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.akeyless_rotated_secret.rsv", "value"),
				),
			},
		},
	})
}

func TestRotatedSecretHashiVaultResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-hashi-vault-rs"
	targetPath := testPath(targetName)
	targetDetailsType := "hashi_target_details"

	expect := map[string]any{
		"vault_url":        "http://127.0.0.1:8200",
		"vault_token":      "test",
		"vault_namespaces": "",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	rsName := "test-rs-hashi-vault"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_rotated_secret_hashivault" "%v" {
			name 					= "%v"
			target_name 			= "%v"
			description 			= "aaaa"
			password_length 		= "12"
			input_rule 			= ["name=in1,rule=validate input"]
			output_rule 			= ["name=out1,rule=mask output"]
			rotation_event_in 		= ["1", "7"]
			use_capital_letters 	= "true"
			use_lower_letters 		= "true"
			use_numbers 			= "true"
			use_special_characters 	= "false"
		}
	`, rsName, rsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_rotated_secret_hashivault" "%v" {
			name 					= "%v"
			target_name 			= "%v"
			description 			= "bbbb"
			password_length 		= "14"
			input_rule 				= ["name=in2,rule=validate input updated"]
			output_rule 			= ["name=out1,rule=mask output updated"]
			rotation_event_in 		= ["2", "8", "14"]
			use_capital_letters 	= "false"
			use_lower_letters 		= "false"
			use_numbers 			= "false"
			use_special_characters 	= "true"
		}
	`, rsName, rsPath, targetPath)
	resourceName := "akeyless_rotated_secret_hashivault." + rsName
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckItemExistsRemotely(rsPath),
					resource.TestCheckResourceAttr(resourceName, "password_length", "12"),
					resource.TestCheckResourceAttr(resourceName, "input_rule.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "input_rule.0", "name=in1,rule=validate input"),
					resource.TestCheckResourceAttr(resourceName, "output_rule.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "output_rule.0", "name=out1,rule=mask output"),
					resource.TestCheckResourceAttr(resourceName, "use_capital_letters", "true"),
					resource.TestCheckResourceAttr(resourceName, "use_lower_letters", "true"),
					resource.TestCheckResourceAttr(resourceName, "use_numbers", "true"),
					resource.TestCheckResourceAttr(resourceName, "use_special_characters", "false"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckItemExistsRemotely(rsPath),
					resource.TestCheckResourceAttr(resourceName, "password_length", "14"),
					resource.TestCheckResourceAttr(resourceName, "input_rule.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "input_rule.0", "name=in2,rule=validate input updated"),
					resource.TestCheckResourceAttr(resourceName, "output_rule.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "output_rule.0", "name=out1,rule=mask output updated"),
					resource.TestCheckResourceAttr(resourceName, "use_capital_letters", "false"),
					resource.TestCheckResourceAttr(resourceName, "use_lower_letters", "false"),
					resource.TestCheckResourceAttr(resourceName, "use_numbers", "false"),
					resource.TestCheckResourceAttr(resourceName, "use_special_characters", "true"),
				),
			},
		},
	})
}
