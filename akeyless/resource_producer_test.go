package akeyless

import (
	"fmt"
	"testing"
)

const (
	GCP_KEY          = "XXXXXXXX"
	GCP_SA_EMAIL     = "XXXXXXXX"
	GCP_TOKEN_SCOPES = "XXXXXXXX"
)

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
			tags 				= ["abc", "def"]
		}
	`, name, itemPath, GCP_SA_EMAIL, GCP_TOKEN_SCOPES, GCP_KEY)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestRotatedSecretResource(t *testing.T) {
	t.Skip("for now the requested values are fictive")

	name := "rotate_test"
	itemPath := testPath(name)

	targetName := "mysql_test"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      		= "%v"
			db_type   		= "mysql"
			host      		= "127.0.0.1"
			port      		= "3306"
			db_name   		= "XXXXXXXX"
			user_name 		= "XXXXXXXX"
			pwd       		= "XXXXXXXX"
		}
		resource "akeyless_rotated_secret" "%v" {
			name 			= "%v"
			target_name 	= "%v"
			rotator_type 	= "target"
			rotated_username = "XXXXXXXX"
			rotated_password = "XXXXXXXX"
			authentication_credentials = "use-target-creds"
			key = "XXXXXXXX"
			depends_on = [
    			akeyless_target_db.%v,
  			]
		}
	`, targetName, targetPath, name, itemPath, targetPath, targetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name      		= "%v"
			db_type   		= "mysql"
			host      		= "127.0.0.1"
			port      		= "3306"
			db_name   		= "XXXXXXXX"
			user_name 		= "XXXXXXXX"
			pwd       		= "XXXXXXXX"
		}
		resource "akeyless_rotated_secret" "%v" {
			name 			= "%v"
			target_name 	= "%v"
			rotator_type 	= "target"
			rotated_username = "XXXXXXXX"
			rotated_password = "XXXXXXXX"
			authentication_credentials = "use-target-creds"
			key 			= "XXXXXXXX"
			tags 			= ["abc", "def"]
			depends_on = [
    			akeyless_target_db.%v,
  			]
		}
	`, targetName, targetPath, name, itemPath, targetPath, targetName)

	tesItemResource(t, config, configUpdate, itemPath)
}
