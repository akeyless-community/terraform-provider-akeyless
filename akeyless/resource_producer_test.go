package akeyless

import (
	"context"
	"fmt"
	"testing"

	"github.com/akeylesslabs/akeyless-go/v2"
)

const (
	GCP_KEY          = "XXXXXXXX"
	GCP_SA_EMAIL     = "XXXXXXXX"
	GCP_TOKEN_SCOPES = "XXXXXXXX"
	KEY              = "XXXXXXXX"
	PRODUCER_NAME    = "terraform-tests/mysql_for_rs_test"
	MYSQL_USERNAME   = "XXXXXXXX"
	MYSQL_PASSWORD   = "XXXXXXXX"
	MYSQL_HOST       = "127.0.0.1"
	MYSQL_PORT       = "3306"
	MYSQL_DBNAME     = "XXXXXXXX"
)

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
