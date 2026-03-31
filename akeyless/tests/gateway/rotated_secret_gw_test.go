package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestRotatedSecretMysqlGw(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_mysql_target"
	targetPath := testPath(targetName)
	rsName := "rs_mysql_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "mysql"
			host      = "%v"
			port      = "%v"
			db_name   = "%v"
			user_name = "%v"
			pwd       = "%v"
		}
		resource "akeyless_rotated_secret_mysql" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath, testutils.DockerMysqlHost, testutils.DockerMysqlPort, testutils.DockerMysqlDB, testutils.DockerMysqlUser, testutils.DockerMysqlPassword,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "mysql"
			host      = "%v"
			port      = "%v"
			db_name   = "%v"
			user_name = "%v"
			pwd       = "%v"
		}
		resource "akeyless_rotated_secret_mysql" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath, testutils.DockerMysqlHost, testutils.DockerMysqlPort, testutils.DockerMysqlDB, testutils.DockerMysqlUser, testutils.DockerMysqlPassword,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretPostgresqlGw(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_pg_target"
	targetPath := testPath(targetName)
	rsName := "rs_pg_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "postgres"
			host      = "%v"
			port      = "%v"
			db_name   = "%v"
			user_name = "%v"
			pwd       = "%v"
		}
		resource "akeyless_rotated_secret_postgresql" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath, testutils.DockerPostgresHost, testutils.DockerPostgresPort, testutils.DockerPostgresDB, testutils.DockerPostgresUser, testutils.DockerPostgresPassword,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "postgres"
			host      = "%v"
			port      = "%v"
			db_name   = "%v"
			user_name = "%v"
			pwd       = "%v"
		}
		resource "akeyless_rotated_secret_postgresql" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath, testutils.DockerPostgresHost, testutils.DockerPostgresPort, testutils.DockerPostgresDB, testutils.DockerPostgresUser, testutils.DockerPostgresPassword,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretMongoGw(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_mongo_target"
	targetPath := testPath(targetName)
	rsName := "rs_mongo_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "mongodb"
			host      = "%v"
			port      = "%v"
			db_name   = "%v"
			user_name = "%v"
			pwd       = "%v"
		}
		resource "akeyless_rotated_secret_mongodb" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath, testutils.DockerMongoHost, testutils.DockerMongoPort, testutils.DockerMongoDB, testutils.DockerMongoUser, testutils.DockerMongoPassword,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "mongodb"
			host      = "%v"
			port      = "%v"
			db_name   = "%v"
			user_name = "%v"
			pwd       = "%v"
		}
		resource "akeyless_rotated_secret_mongodb" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath, testutils.DockerMongoHost, testutils.DockerMongoPort, testutils.DockerMongoDB, testutils.DockerMongoUser, testutils.DockerMongoPassword,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretMssqlGw(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_mssql_target"
	targetPath := testPath(targetName)
	rsName := "rs_mssql_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "mssql"
			host      = "%v"
			port      = "%v"
			db_name   = "%v"
			user_name = "%v"
			pwd       = "%v"
		}
		resource "akeyless_rotated_secret_mssql" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath, testutils.DockerMssqlHost, testutils.DockerMssqlPort, testutils.DockerMssqlDB, testutils.DockerMssqlUser, testutils.DockerMssqlPassword,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "mssql"
			host      = "%v"
			port      = "%v"
			db_name   = "%v"
			user_name = "%v"
			pwd       = "%v"
		}
		resource "akeyless_rotated_secret_mssql" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath, testutils.DockerMssqlHost, testutils.DockerMssqlPort, testutils.DockerMssqlDB, testutils.DockerMssqlUser, testutils.DockerMssqlPassword,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}

func TestRotatedSecretCassandraGw(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	targetName := "rs_cass_target"
	targetPath := testPath(targetName)
	rsName := "rs_cass_test"
	rsPath := testPath(rsName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "cassandra"
			host      = "%v"
			port      = "%v"
			user_name = "%v"
			pwd       = "%v"
		}
		resource "akeyless_rotated_secret_cassandra" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath, testutils.DockerCassandraHost, testutils.DockerCassandraPort, testutils.DockerCassandraUser, testutils.DockerCassandraPassword,
		rsName, rsPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      = "%v"
			db_type   = "cassandra"
			host      = "%v"
			port      = "%v"
			user_name = "%v"
			pwd       = "%v"
		}
		resource "akeyless_rotated_secret_cassandra" "%v" {
			name                       = "%v"
			target_name                = "%v"
			rotator_type               = "target"
			authentication_credentials = "use-target-creds"
			tags                       = ["test1", "test2"]
			depends_on = [akeyless_target_db.%v]
		}
	`, targetName, targetPath, testutils.DockerCassandraHost, testutils.DockerCassandraPort, testutils.DockerCassandraUser, testutils.DockerCassandraPassword,
		rsName, rsPath, targetPath, targetName)

	testutils.TestItemResource(t, providerFactories, rsPath, config, configUpdate)
}
