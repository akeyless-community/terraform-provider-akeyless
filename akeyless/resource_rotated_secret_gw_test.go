package akeyless

import (
	"fmt"
	"testing"
)

func TestRotatedSecretMysqlGw(t *testing.T) {
	skipIfNoGateway(t)
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
	`, targetName, targetPath, dockerMysqlHost, dockerMysqlPort, dockerMysqlDB, dockerMysqlUser, dockerMysqlPassword,
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
	`, targetName, targetPath, dockerMysqlHost, dockerMysqlPort, dockerMysqlDB, dockerMysqlUser, dockerMysqlPassword,
		rsName, rsPath, targetPath, targetName)

	testItemResource(t, rsPath, config, configUpdate)
}

func TestRotatedSecretPostgresqlGw(t *testing.T) {
	skipIfNoGateway(t)
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
	`, targetName, targetPath, dockerPostgresHost, dockerPostgresPort, dockerPostgresDB, dockerPostgresUser, dockerPostgresPassword,
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
	`, targetName, targetPath, dockerPostgresHost, dockerPostgresPort, dockerPostgresDB, dockerPostgresUser, dockerPostgresPassword,
		rsName, rsPath, targetPath, targetName)

	testItemResource(t, rsPath, config, configUpdate)
}

func TestRotatedSecretMongoGw(t *testing.T) {
	skipIfNoGateway(t)
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
	`, targetName, targetPath, dockerMongoHost, dockerMongoPort, dockerMongoDB, dockerMongoUser, dockerMongoPassword,
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
	`, targetName, targetPath, dockerMongoHost, dockerMongoPort, dockerMongoDB, dockerMongoUser, dockerMongoPassword,
		rsName, rsPath, targetPath, targetName)

	testItemResource(t, rsPath, config, configUpdate)
}

func TestRotatedSecretMssqlGw(t *testing.T) {
	skipIfNoGateway(t)
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
	`, targetName, targetPath, dockerMssqlHost, dockerMssqlPort, dockerMssqlDB, dockerMssqlUser, dockerMssqlPassword,
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
	`, targetName, targetPath, dockerMssqlHost, dockerMssqlPort, dockerMssqlDB, dockerMssqlUser, dockerMssqlPassword,
		rsName, rsPath, targetPath, targetName)

	testItemResource(t, rsPath, config, configUpdate)
}

func TestRotatedSecretCassandraGw(t *testing.T) {
	skipIfNoGateway(t)
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
	`, targetName, targetPath, dockerCassandraHost, dockerCassandraPort, dockerCassandraUser, dockerCassandraPassword,
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
	`, targetName, targetPath, dockerCassandraHost, dockerCassandraPort, dockerCassandraUser, dockerCassandraPassword,
		rsName, rsPath, targetPath, targetName)

	testItemResource(t, rsPath, config, configUpdate)
}
