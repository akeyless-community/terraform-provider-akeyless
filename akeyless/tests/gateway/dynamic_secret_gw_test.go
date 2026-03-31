package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestDynamicSecretMysql(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "ds_mysql_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mysql" "%v" {
			name           = "%v"
			mysql_username = "%v"
			mysql_password = "%v"
			mysql_host     = "%v"
			mysql_port     = "%v"
			mysql_dbname   = "%v"
			user_ttl       = "30m"
		}
	`, name, itemPath, testutils.DockerMysqlUser, testutils.DockerMysqlPassword, testutils.DockerMysqlHost, testutils.DockerMysqlPort, testutils.DockerMysqlDB)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mysql" "%v" {
			name           = "%v"
			mysql_username = "%v"
			mysql_password = "%v"
			mysql_host     = "%v"
			mysql_port     = "%v"
			mysql_dbname   = "%v"
			user_ttl       = "60m"
			tags           = ["test1", "test2"]
		}
	`, name, itemPath, testutils.DockerMysqlUser, testutils.DockerMysqlPassword, testutils.DockerMysqlHost, testutils.DockerMysqlPort, testutils.DockerMysqlDB)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretPostgresql(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "ds_postgres_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_postgresql" "%v" {
			name                = "%v"
			postgresql_username = "%v"
			postgresql_password = "%v"
			postgresql_host     = "%v"
			postgresql_port     = "%v"
			postgresql_db_name  = "%v"
			user_ttl            = "30m"
		}
	`, name, itemPath, testutils.DockerPostgresUser, testutils.DockerPostgresPassword, testutils.DockerPostgresHost, testutils.DockerPostgresPort, testutils.DockerPostgresDB)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_postgresql" "%v" {
			name                = "%v"
			postgresql_username = "%v"
			postgresql_password = "%v"
			postgresql_host     = "%v"
			postgresql_port     = "%v"
			postgresql_db_name  = "%v"
			user_ttl            = "60m"
			tags                = ["test1", "test2"]
		}
	`, name, itemPath, testutils.DockerPostgresUser, testutils.DockerPostgresPassword, testutils.DockerPostgresHost, testutils.DockerPostgresPort, testutils.DockerPostgresDB)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretMongo(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "ds_mongo_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mongodb" "%v" {
			name                   = "%v"
			mongodb_username       = "%v"
			mongodb_password       = "%v"
			mongodb_host_port      = "%v:%v"
			mongodb_default_auth_db = "admin"
			mongodb_name           = "%v"
			user_ttl               = "30m"
		}
	`, name, itemPath, testutils.DockerMongoUser, testutils.DockerMongoPassword, testutils.DockerMongoHost, testutils.DockerMongoPort, testutils.DockerMongoDB)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mongodb" "%v" {
			name                   = "%v"
			mongodb_username       = "%v"
			mongodb_password       = "%v"
			mongodb_host_port      = "%v:%v"
			mongodb_default_auth_db = "admin"
			mongodb_name           = "%v"
			user_ttl               = "60m"
			tags                   = ["test1", "test2"]
		}
	`, name, itemPath, testutils.DockerMongoUser, testutils.DockerMongoPassword, testutils.DockerMongoHost, testutils.DockerMongoPort, testutils.DockerMongoDB)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretMssql(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "ds_mssql_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mssql" "%v" {
			name           = "%v"
			mssql_username = "%v"
			mssql_password = "%v"
			mssql_host     = "%v"
			mssql_port     = "%v"
			mssql_dbname   = "%v"
			user_ttl       = "30m"
		}
	`, name, itemPath, testutils.DockerMssqlUser, testutils.DockerMssqlPassword, testutils.DockerMssqlHost, testutils.DockerMssqlPort, testutils.DockerMssqlDB)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mssql" "%v" {
			name           = "%v"
			mssql_username = "%v"
			mssql_password = "%v"
			mssql_host     = "%v"
			mssql_port     = "%v"
			mssql_dbname   = "%v"
			user_ttl       = "60m"
			tags           = ["test1", "test2"]
		}
	`, name, itemPath, testutils.DockerMssqlUser, testutils.DockerMssqlPassword, testutils.DockerMssqlHost, testutils.DockerMssqlPort, testutils.DockerMssqlDB)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretRedis(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "ds_redis_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_redis" "%v" {
			name     = "%v"
			username = "%v"
			password = "%v"
			host     = "%v"
			port     = "%v"
			user_ttl = "30m"
		}
	`, name, itemPath, testutils.DockerRedisUser, testutils.DockerRedisPassword, testutils.DockerRedisHost, testutils.DockerRedisPort)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_redis" "%v" {
			name     = "%v"
			username = "%v"
			password = "%v"
			host     = "%v"
			port     = "%v"
			user_ttl = "60m"
			tags     = ["test1", "test2"]
		}
	`, name, itemPath, testutils.DockerRedisUser, testutils.DockerRedisPassword, testutils.DockerRedisHost, testutils.DockerRedisPort)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretCassandra(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "ds_cassandra_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_cassandra" "%v" {
			name               = "%v"
			cassandra_username = "%v"
			cassandra_password = "%v"
			cassandra_hosts    = "%v"
			cassandra_port     = "%v"
			user_ttl           = "30m"
		}
	`, name, itemPath, testutils.DockerCassandraUser, testutils.DockerCassandraPassword, testutils.DockerCassandraHost, testutils.DockerCassandraPort)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_cassandra" "%v" {
			name               = "%v"
			cassandra_username = "%v"
			cassandra_password = "%v"
			cassandra_hosts    = "%v"
			cassandra_port     = "%v"
			user_ttl           = "60m"
			tags               = ["test1", "test2"]
		}
	`, name, itemPath, testutils.DockerCassandraUser, testutils.DockerCassandraPassword, testutils.DockerCassandraHost, testutils.DockerCassandraPort)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretOracle(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "ds_oracle_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_oracle" "%v" {
			name            = "%v"
			oracle_username = "admin"
			oracle_password = "DummyPass123"
			oracle_host     = "oracle-db.example.com"
			oracle_port     = "1521"
			oracle_service_name = "ORCL"
			user_ttl        = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_oracle" "%v" {
			name            = "%v"
			oracle_username = "admin"
			oracle_password = "DummyPass123"
			oracle_host     = "oracle-db.example.com"
			oracle_port     = "1521"
			oracle_service_name = "ORCL"
			user_ttl        = "60m"
			tags            = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretHanaDb(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "ds_hana_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_hana_db" "%v" {
			name             = "%v"
			hanadb_username  = "SYSTEM"
			hanadb_password  = "DummyPass123"
			hanadb_host      = "hana-db.example.com"
			hanadb_port      = "30015"
			user_ttl         = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_hana_db" "%v" {
			name             = "%v"
			hanadb_username  = "SYSTEM"
			hanadb_password  = "DummyPass123"
			hanadb_host      = "hana-db.example.com"
			hanadb_port      = "30015"
			user_ttl         = "60m"
			tags             = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretRedshift(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "ds_redshift_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_redshift" "%v" {
			name              = "%v"
			redshift_username = "admin"
			redshift_password = "DummyPass123"
			redshift_host     = "redshift-cluster.example.com"
			redshift_port     = "5439"
			redshift_db_name  = "testdb"
			user_ttl          = "30m"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_redshift" "%v" {
			name              = "%v"
			redshift_username = "admin"
			redshift_password = "DummyPass123"
			redshift_host     = "redshift-cluster.example.com"
			redshift_port     = "5439"
			redshift_db_name  = "testdb"
			user_ttl          = "60m"
			tags              = ["test1", "test2"]
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestDynamicSecretRabbitmq(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	name := "ds_rabbitmq_test"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_rabbitmq" "%v" {
			name                           = "%v"
			rabbitmq_admin_user            = "%v"
			rabbitmq_admin_pwd             = "%v"
			rabbitmq_server_uri            = "%v"
			rabbitmq_user_tags             = "management"
			rabbitmq_user_conf_permission  = ".*"
			rabbitmq_user_read_permission  = ".*"
			rabbitmq_user_write_permission = ".*"
			user_ttl                       = "30m"
		}
	`, name, itemPath, testutils.DockerRabbitmqUser, testutils.DockerRabbitmqPassword, testutils.DockerRabbitmqURI)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_rabbitmq" "%v" {
			name                           = "%v"
			rabbitmq_admin_user            = "%v"
			rabbitmq_admin_pwd             = "%v"
			rabbitmq_server_uri            = "%v"
			rabbitmq_user_tags             = "administrator"
			rabbitmq_user_conf_permission  = ".*"
			rabbitmq_user_read_permission  = ".*"
			rabbitmq_user_write_permission = ".*"
			user_ttl                       = "60m"
			tags                           = ["test1", "test2"]
		}
	`, name, itemPath, testutils.DockerRabbitmqUser, testutils.DockerRabbitmqPassword, testutils.DockerRabbitmqURI)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}
