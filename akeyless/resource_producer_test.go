package akeyless

import (
	"context"
	"fmt"
	"testing"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
)

const (
	GCP_KEY                = "XXXXXXXX"
	GCP_SA_EMAIL           = "XXXXXXXX"
	GCP_TOKEN_SCOPES       = "XXXXXXXX"
	KEY                    = "XXXXXXXX"
	PRODUCER_NAME          = "terraform-tests/mysql_for_rs_test"
	MYSQL_USERNAME         = "XXXXXXXX"
	MYSQL_PASSWORD         = "XXXXXXXX"
	MYSQL_HOST             = "127.0.0.1"
	MYSQL_PORT             = "3306"
	MYSQL_DBNAME           = "XXXXXXXX"
	GITHUB_INSTALL_ID      = 1234
	GITHUB_INSTALL_REPO    = "XXXXXXXX"
	GITHUB_APP_ID          = 1234
	GITHUB_APP_KEY         = "XXXXXXXX"
	DOCKERHUB_USERNAME     = "XXXXXXXX"
	DOCKERHUB_PASSWORD     = "XXXXXXXX"
	DOCKERHUB_TOKEN_SCOPES = `"repo:read , repo:write"`
	SF_ACCOUNT             = "xx11111.us-east-2.aws"
	SF_USERNAME            = "xxxxxxxx"
	SF_PASSWORD            = "yyyyyyyy"
	SF_DBNAME              = "XXXXXXXX"
)

var GITHUB_TOKEN_PERM = `["contents=read", "issues=write", "actions=read"]`
var GITHUB_TOKEN_REPO = `["github-producer-test1", "github-producer-test2"]`

var mysql_attr = fmt.Sprintf(`
	mysql_username	= "%v"
	mysql_password	= "%v"
	mysql_host		= "%v"
	mysql_port		= "%v"
	mysql_dbname	= "%v"
`, MYSQL_USERNAME, MYSQL_PASSWORD, MYSQL_HOST, MYSQL_PORT, MYSQL_DBNAME)

var db_attr = fmt.Sprintf(`
	db_type   		= "mysql"
	host      		= "%v"
	port      		= "%v"
	db_name   		= "%v"
`, MYSQL_HOST, MYSQL_PORT, MYSQL_DBNAME)

func TestSnowflakeProducerResource(t *testing.T) {

	t.Skip("for now the requested values are fictive")

	name := "snowflake_test"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_producer_snowflake" "%v" {
			name 				= "%v"
			account 			= "%v"
			account_username 	= "%v"
			account_password 	= "%v"
			db_name 			= "%v"
			warehouse 			= "aaaa"
			role 				= "bbbb"
		}
		data "akeyless_dynamic_secret" "secret" {
			path 		= "%v"
			depends_on 	= [
				akeyless_producer_snowflake.%v,
			]
		}
	`, name, itemPath, SF_ACCOUNT, SF_USERNAME, SF_PASSWORD, SF_DBNAME, itemPath, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_producer_snowflake" "%v" {
			name 				= "%v"
			account 			= "%v"
			account_username 	= "%v"
			account_password 	= "%v"
			db_name 			= "%v"
			warehouse 			= "aaaaaa"
			role 				= "bbbbbb"
			user_ttl 			= "12h"
			tags 				= ["aaa" , "bbb"]
		}
		data "akeyless_dynamic_secret" "secret" {
			path 		= "%v"
			depends_on 	= [
				akeyless_producer_snowflake.%v,
			]
		}
	`, name, itemPath, SF_ACCOUNT, SF_USERNAME, SF_PASSWORD, SF_DBNAME, itemPath, name)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestRabbitMQProducerResource(t *testing.T) {

	t.Skip("wait for sdk update")

	name := "rabbitmq_test"
	itemPath := testPath(name)
	serverUrl := "http://127.0.0.1:15672"

	config := fmt.Sprintf(`
		resource "akeyless_producer_rabbitmq" "%v" {
			name                            = "%v"
			rabbitmq_server_uri             = "%v"
			rabbitmq_user_conf_permission   = ".*"
			rabbitmq_user_write_permission  = ".*"
			rabbitmq_user_read_permission   = ".*"
			rabbitmq_admin_user             = "guest"
			rabbitmq_admin_pwd              = "guest"
		}
	`, name, itemPath, serverUrl)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_producer_rabbitmq" "%v" {
			name                            = "%v"
			rabbitmq_server_uri             = "%v"
			rabbitmq_user_conf_permission   = ".*"
			rabbitmq_user_write_permission  = ".*"
			rabbitmq_user_read_permission   = ".*"
			rabbitmq_admin_user             = "guest"
			rabbitmq_admin_pwd              = "guest"
			tags                 			= ["abc", "def"]
			user_ttl 						= 80
			secure_access_enable 			= "true"
			secure_access_web_browsing    	= "true"
			secure_access_url   			= "http://blabla.com"
		}
	`, name, itemPath, serverUrl)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestHanadbProducerResource(t *testing.T) {

	t.Skip("for now the requested values are fictive")

	name := "hanadb_test"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_producer_hanadb" "%v" {
			name			= "%v"
			hana_dbname     = "XXXXXX"
			hanadb_username = "YYYYYY"
			hanadb_password = "12345678"
			hanadb_host     = "127.0.0.1"
			hanadb_port     = "30013"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_producer_hanadb" "%v" {
			name 			= "%v"
			hana_dbname     = "XXXXXX"
			hanadb_username = "YYYYYY"
			hanadb_password = "12345678"
			hanadb_host     = "127.0.0.1"
			hanadb_port     = "30013"
			secure_access_enable 	= "true"
			secure_access_web    	= "true"
			secure_access_host   	= ["http://abcdef.com"]
			tags                 	= ["aaa", "bbb"]
		}
	`, name, itemPath)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestGithubProducerResource(t *testing.T) {

	t.Skip("for now the requested values are fictive")

	name := "github_test"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_producer_github" "%v" {
			name            		= "%v"
			installation_id 		= %v
			token_permissions 		= %v
			github_app_id 			= %v
			github_app_private_key 	= "%v"
		}
	`, name, itemPath, GITHUB_INSTALL_ID, GITHUB_TOKEN_PERM, GITHUB_APP_ID, GITHUB_APP_KEY)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_producer_github" "%v" {
			name            		= "%v"
			installation_repository = "%v"
			token_repositories 		= %v
			github_app_id 			= %v
			github_app_private_key 	= "%v"
		}
	`, name, itemPath, GITHUB_INSTALL_REPO, GITHUB_TOKEN_REPO, GITHUB_APP_ID, GITHUB_APP_KEY)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestDockerhubProducerResource(t *testing.T) {

	t.Skip("for now the requested values are fictive")

	name := "dockerhub_test"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_producer_dockerhub" "%v" {
			name            		= "%v"
			dockerhub_username 		= "%v"
			dockerhub_password 		= "%v"
		}
	`, name, itemPath, DOCKERHUB_USERNAME, DOCKERHUB_PASSWORD)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_producer_dockerhub" "%v" {
			name            		= "%v"
			dockerhub_username 		= "%v"
			dockerhub_password 		= "%v"
			tags 					= ["abc", "def"]
			dockerhub_token_scopes 	= %v
		}
	`, name, itemPath, DOCKERHUB_USERNAME, DOCKERHUB_PASSWORD, DOCKERHUB_TOKEN_SCOPES)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestCustomProducerResource(t *testing.T) {
	t.Skip("must run with server listen the following addresses")

	name := "custom_test"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_producer_custom" "%v" {
			name            = "%v"
			create_sync_url = "http://localhost:7890/sync/create"
			revoke_sync_url = "http://localhost:7890/sync/revoke"
			payload         = "aaaa"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_producer_custom" "%v" {
			name            = "%v"
			create_sync_url = "http://localhost:7890/sync/create"
			revoke_sync_url = "http://localhost:7890/sync/revoke"
			payload         = "bbbb"
			enable_admin_rotation = "true"
			timeout_sec 	= "30"
			user_ttl 		= "10"
			tags 			= ["abc", "def"]
		}
	`, name, itemPath)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestMySqlProducerResource(t *testing.T) {

	t.Skip("for now the requested values are fictive")

	name := "mysql_test"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_producer_mysql" "%v" {
			name					= "%v"
			%v
		}
`, name, itemPath, mysql_attr)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_producer_mysql" "%v" {
			name 					= "%v"
			%v
			secure_access_enable 	= "true"
			secure_access_web    	= "true"
			secure_access_host   	= ["http://jdjfjf.com"]
			tags                 	= ["t1s", "ff32"]
		}
	`, name, itemPath, mysql_attr)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestGcpProducerResource(t *testing.T) {

	t.Skip("for now the requested values are fictive")

	name := "gcp_test"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_producer_gcp" "%v" {
			name 				= "%v"
			gcp_sa_email 		= "%v"
			gcp_key_algo 		= "KEY_ALG_RSA_1024"
			gcp_cred_type 		= "token"
			gcp_token_scopes 	= "%v"
			gcp_key 			= "%v"
		}
	`, name, itemPath, GCP_SA_EMAIL, GCP_TOKEN_SCOPES, GCP_KEY)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_producer_gcp" "%v" {
			name 				= "%v"
			gcp_sa_email 		= "%v"
			gcp_key_algo 		= "KEY_ALG_RSA_1024"
			gcp_cred_type 		= "token"
			gcp_token_scopes 	= "%v"
			gcp_key 			= "%v"
			tags 				= ["t1s", "ff32"]
		}
	`, name, itemPath, GCP_SA_EMAIL, GCP_TOKEN_SCOPES, GCP_KEY)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestRotatedSecretResource(t *testing.T) {

	t.Skip("for now the requested values are fictive")

	client, token := getClient()
	user, password := generateDynamicSecret(client, token)

	rsName := "rotate_test"
	rsPath := testPath(rsName)

	targetName := "mysql_test"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      		= "%v"
			%v
			user_name     	= "%v"
  			pwd       		= "%v"
		}
		resource "akeyless_rotated_secret" "%v" {
			name 			= "%v"
			target_name 	= "%v"
			rotator_type 	= "target"
			rotated_username = akeyless_target_db.%v.user_name
  			rotated_password = akeyless_target_db.%v.pwd
			authentication_credentials = "use-target-creds"
			key 			= "%v"
			depends_on = [
    			akeyless_target_db.%v,
  			]
		}
	`, targetName, targetPath, db_attr, user, password, rsName, rsPath, targetPath, targetName, targetName, KEY, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      		= "%v"
			%v
			user_name     	= "%v"
  			pwd       		= "%v"
		}
		resource "akeyless_rotated_secret" "%v" {
			name 			= "%v"
			target_name 	= "%v"
			rotator_type 	= "target"
			rotated_username = akeyless_target_db.%v.user_name
			rotated_password = akeyless_target_db.%v.pwd
			authentication_credentials = "use-user-creds"
			key 			= "%v"
			auto_rotate		= "true"
			rotation_interval = "2"
			metadata 		= "bbbb"
			tags 			= ["abc", "def"]
			depends_on = [
				akeyless_target_db.%v,
			]
		}
	`, targetName, targetPath, db_attr, user, password, rsName, rsPath, targetPath, targetName, targetName, KEY, targetName)

	tesItemResource(t, config, configUpdate, rsPath)

	deleteProducer(client, token)
}

func getClient() (*akeyless.V2ApiService, string) {
	p, err := getProviderMeta()
	if err != nil {
		panic(err)
	}
	return p.client, *p.token
}

func generateDynamicSecret(client *akeyless.V2ApiService, token string) (string, string) {

	producerBody := akeyless.GatewayCreateProducerMySQL{
		Token:         &token,
		Name:          PRODUCER_NAME,
		MysqlUsername: akeyless.PtrString(MYSQL_USERNAME),
		MysqlPassword: akeyless.PtrString(MYSQL_PASSWORD),
		MysqlHost:     akeyless.PtrString(MYSQL_HOST),
		MysqlPort:     akeyless.PtrString(MYSQL_PORT),
		MysqlDbname:   akeyless.PtrString(MYSQL_DBNAME),
	}
	_, _, err := client.GatewayCreateProducerMySQL(context.Background()).Body(producerBody).Execute()
	if err != nil {
		panic(err)
	}

	dynamicSecret := akeyless.GetDynamicSecretValue{
		Name: PRODUCER_NAME,
	}
	value, _, err := client.GetDynamicSecretValue(context.Background()).Body(dynamicSecret).Execute()
	if err != nil {
		panic(err)
	}

	return value["user"], value["password"]
}

func deleteProducer(client *akeyless.V2ApiService, token string) {

	toDelete := akeyless.DeleteItem{
		Name:              PRODUCER_NAME,
		Token:             &token,
		DeleteImmediately: akeyless.PtrBool(true),
		DeleteInDays:      akeyless.PtrInt64(-1),
	}
	_, _, err := client.DeleteItem(context.Background()).Body(toDelete).Execute()
	if err != nil {
		fmt.Println("failed to delete producer:", err)
	} else {
		fmt.Println("deleted", PRODUCER_NAME)
	}
}

func checkActiveStatusRemotely(t *testing.T, path string, isActive bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GatewayGetProducer{
			Name:  path,
			Token: &token,
		}

		res, _, err := client.GatewayGetProducer(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}

		assert.NoError(t, err)
		assert.NotNil(t, res, "producer details must not be nil")
		assert.NotNil(t, res.Active, "producer Active details must not be nil")
		assert.Equal(t, isActive, *res.Active)
		return nil
	}
}
