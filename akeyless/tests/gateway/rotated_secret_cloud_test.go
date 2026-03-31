// generated file
package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestRotatedSecretAws(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_aws_target"
	targetPath := testPath(targetName)
	rsName := "rs_aws_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_aws" "%v" {
			name          = "%v"
			access_key_id = "test"
			access_key    = "test"
		}
		resource "akeyless_rotated_secret_aws" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "api-key"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_aws.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_aws" "%v" {
			name          = "%v"
			access_key_id = "test"
			access_key    = "test"
		}
		resource "akeyless_rotated_secret_aws" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "api-key"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_aws.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretAzure(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_azure_target"
	targetPath := testPath(targetName)
	rsName := "rs_azure_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_azure" "%v" {
			name              = "%v"
			tenant_id         = "00000000-0000-0000-0000-000000000001"
			client_id         = "00000000-0000-0000-0000-000000000002"
			client_secret     = "dummy-client-secret"
		}
		resource "akeyless_rotated_secret_azure" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "api-key"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_azure.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_azure" "%v" {
			name              = "%v"
			tenant_id         = "00000000-0000-0000-0000-000000000001"
			client_id         = "00000000-0000-0000-0000-000000000002"
			client_secret     = "dummy-client-secret"
		}
		resource "akeyless_rotated_secret_azure" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "api-key"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_azure.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretCustom(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_custom_target"
	targetPath := testPath(targetName)
	rsName := "rs_custom_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_web" "%v" {
			name = "%v"
			url  = "https://webhook.example.com"
		}
		resource "akeyless_rotated_secret_custom" "%v" {
			name        = "%v"
			target_name = "%v"
			depends_on  = [akeyless_target_web.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_web" "%v" {
			name = "%v"
			url  = "https://webhook.example.com"
		}
		resource "akeyless_rotated_secret_custom" "%v" {
			name        = "%v"
			target_name = "%v"
			tags        = ["test1", "test2"]
			depends_on  = [akeyless_target_web.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretDockerhub(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_dockerhub_target"
	targetPath := testPath(targetName)
	rsName := "rs_dockerhub_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_dockerhub" "%v" {
			name               = "%v"
			dockerhub_username = "dummyuser"
			dockerhub_password = "DummyPass123"
		}
		resource "akeyless_rotated_secret_dockerhub" "%v" {
			name        = "%v"
			target_name = "%v"
			depends_on  = [akeyless_target_dockerhub.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_dockerhub" "%v" {
			name               = "%v"
			dockerhub_username = "dummyuser"
			dockerhub_password = "DummyPass123"
		}
		resource "akeyless_rotated_secret_dockerhub" "%v" {
			name        = "%v"
			target_name = "%v"
			tags        = ["test1", "test2"]
			depends_on  = [akeyless_target_dockerhub.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretHanadb(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_hana_target"
	targetPath := testPath(targetName)
	rsName := "rs_hana_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "hanadb"
			host      = "hana-db.example.com"
			port      = "30015"
			db_name   = "SYSTEMDB"
			user_name = "SYSTEM"
			pwd       = "DummyPass123"
		}
		resource "akeyless_rotated_secret_hanadb" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "hanadb"
			host      = "hana-db.example.com"
			port      = "30015"
			db_name   = "SYSTEMDB"
			user_name = "SYSTEM"
			pwd       = "DummyPass123"
		}
		resource "akeyless_rotated_secret_hanadb" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretLdap(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_ldap_target"
	targetPath := testPath(targetName)
	rsName := "rs_ldap_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_ldap" "%v" {
			name             = "%v"
			ldap_url         = "ldap://ldap.example.com:389"
			bind_dn          = "cn=admin,dc=example,dc=com"
			bind_dn_password = "DummyPass123"
		}
		resource "akeyless_rotated_secret_ldap" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "ldap"
			rotated_username           = "cn=rotate,dc=example,dc=com"
			rotated_password           = "DummyRotatePass123"
			user_dn                    = "ou=users,dc=example,dc=com"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_ldap.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_ldap" "%v" {
			name             = "%v"
			ldap_url         = "ldap://ldap.example.com:389"
			bind_dn          = "cn=admin,dc=example,dc=com"
			bind_dn_password = "DummyPass123"
		}
		resource "akeyless_rotated_secret_ldap" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "ldap"
			rotated_username           = "cn=rotate,dc=example,dc=com"
			rotated_password           = "DummyRotatePass123"
			user_dn                    = "ou=users,dc=example,dc=com"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_ldap.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretOracle(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_oracle_target"
	targetPath := testPath(targetName)
	rsName := "rs_oracle_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "oracle"
			host      = "oracle-db.example.com"
			port      = "1521"
			user_name = "admin"
			pwd       = "DummyPass123"
		}
		resource "akeyless_rotated_secret_oracle" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "oracle"
			host      = "oracle-db.example.com"
			port      = "1521"
			user_name = "admin"
			pwd       = "DummyPass123"
		}
		resource "akeyless_rotated_secret_oracle" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretRedis(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_redis_target"
	targetPath := testPath(targetName)
	rsName := "rs_redis_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "redis"
			host      = "%v"
			port      = "%v"
			user_name = "%v"
			pwd       = "%v"
		}
		resource "akeyless_rotated_secret_redis" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath, testutils.DockerRedisHost, testutils.DockerRedisPort, testutils.DockerRedisUser, testutils.DockerRedisPassword,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "redis"
			host      = "%v"
			port      = "%v"
			user_name = "%v"
			pwd       = "%v"
		}
		resource "akeyless_rotated_secret_redis" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath, testutils.DockerRedisHost, testutils.DockerRedisPort, testutils.DockerRedisUser, testutils.DockerRedisPassword,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretRedshift(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_redshift_target"
	targetPath := testPath(targetName)
	rsName := "rs_redshift_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "redshift"
			host      = "redshift-cluster.example.com"
			port      = "5439"
			user_name = "admin"
			pwd       = "DummyPass123"
		}
		resource "akeyless_rotated_secret_redshift" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "redshift"
			host      = "redshift-cluster.example.com"
			port      = "5439"
			user_name = "admin"
			pwd       = "DummyPass123"
		}
		resource "akeyless_rotated_secret_redshift" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretSnowflake(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_snowflake_target"
	targetPath := testPath(targetName)
	rsName := "rs_snowflake_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "snowflake"
			host      = "test-account.snowflakecomputing.com"
			port      = "443"
			user_name = "admin"
			pwd       = "DummyPass123"
		}
		resource "akeyless_rotated_secret_snowflake" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "password"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "snowflake"
			host      = "test-account.snowflakecomputing.com"
			port      = "443"
			user_name = "admin"
			pwd       = "DummyPass123"
		}
		resource "akeyless_rotated_secret_snowflake" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "password"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretSsh(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_ssh_target"
	targetPath := testPath(targetName)
	rsName := "rs_ssh_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_ssh" "%v" {
			name     = "%v"
			host     = "ssh.example.com"
			port     = "22"
			ssh_username = "admin"
			ssh_password = "DummyPass123"
		}
		resource "akeyless_rotated_secret_ssh" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_ssh.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_ssh" "%v" {
			name     = "%v"
			host     = "ssh.example.com"
			port     = "22"
			ssh_username = "admin"
			ssh_password = "DummyPass123"
		}
		resource "akeyless_rotated_secret_ssh" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_ssh.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretWindows(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_windows_target"
	targetPath := testPath(targetName)
	rsName := "rs_windows_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_windows" "%v" {
			name     = "%v"
			hostname = "windows.example.com"
			username = "administrator"
			password = "DummyPass123"
		}
		resource "akeyless_rotated_secret_windows" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_windows.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_windows" "%v" {
			name     = "%v"
			hostname = "windows.example.com"
			username = "administrator"
			password = "DummyPass123"
		}
		resource "akeyless_rotated_secret_windows" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_windows.%v]
		}
	`, targetName, targetPath,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}
