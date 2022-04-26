package akeyless

import (
	"fmt"
	"testing"
)

const (
	GCP_KEY          = "ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsCiAgInByb2plY3RfaWQiOiAiYWtleWxlc3MtdGVzdC1lbnYiLAogICJwcml2YXRlX2tleV9pZCI6ICJiMzM5ZDliMGUxYWU3YWY2N2EwMTMzYzNkNWMxYmZkYzE2MWFkNGU0IiwKICAicHJpdmF0ZV9rZXkiOiAiLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXG5NSUlFdmdJQkFEQU5CZ2txaGtpRzl3MEJBUUVGQUFTQ0JLZ3dnZ1NrQWdFQUFvSUJBUUNrWEhQNEJOZndnaGtqXG5aRlRya3NjSkFIS2pocUFvdkVkZGRRQU5nelk5b0R4dzBXZHpuL0R6VG1XUWxhVGE0aUpoVFNxckd1ck9FUEMzXG5YZlJBcGlvMnNOemlxNzJ5YkYwZjRCYkdINHRZTk0yMHloaDdEUEsxS1Btdk5nTFFzY1VLbnkzUDlxUzdhelRHXG5uaXR3MEwzWDk2cFVXc1hGL1l6YlpFaWdndHJiVU5peU12amNxcGJFVk1UVWdwUURFSHNCSGFsY2g1WTJnYVVIXG4rQlorVXowdEZHL1I3QmpNY2xReWxpb2FYMlZDaE9oZWlLZ2ZRWEZ0SWdnUE1tZWFKYnZzekkvUVBsaEphVXZRXG55NEdtdlZYYmE0cW01MGVoc0FWd0wzUkY5TGVockhjMExWaGh3Rkl4VnRwY1RKRGM1ZHJFMWFQTVVxVzlZcXNBXG4zUlJWY1B3YkFnTUJBQUVDZ2dFQUEvbWNjR1lsbHRKK3F5VjFERkY3Y05OSzhudUNDaG9ybTY0RnQwM3lGT0Y0XG5OTDVMd3pjZUM3UmNybmVBQ2k4bjU3U0hFS1pSQVhUVmJZbmZLMlVaWmtNMnhHQ2s4TmpBRTlKR21yb09rNjZMXG5QeEVZTUhtcXNRanhxUFFrYzBtcFcwMW9QVHhZMVpPTkxqU0xGbXBsL1FBblpXemdsWjVCTnRraERJaTlwRW94XG5VdmttcG1yL3U4Q0JINDQ4NmdhdXpXR215SkZnZWlhdDgwZTZkR1k1MkhaWlAwRlhieTBUQlVHSFBtb01HTzU0XG4zUEFkY1d2L3dXS3JJU21pNEU4dFEyNUtqMEhOVUljM0JlZ1JVQ2g5N280aTNEK01sNS9GT0VGT1NxYzMrWTdRXG5TOU5STHdJaU43MDMwTnNKR3E1dXM0R2JJVXgwQ2E0VktVVktMN1JPV1FLQmdRRFpwS2UxOHp4Y2lJaUVTRDlGXG5PVTJybnZINlRzazUya2s2KzB2VVFub09KTjB5eUQxZURlNzc4K1dKYm9uZGxDdnJ3bFoyRVVCWDZLSDZwb3BjXG5hRElMaGFaU0Q2M0t6VWZJZk1sdnJxY20rMFJPM2paQXE3NTVOVlVldWJXWUVjektZQ2F0ZWFYQTlWS1JtRnBjXG5CTkFQUUk3MVljS20zbERmRkFUMlJwQTZqd0tCZ1FEQlUrTXZtWW1wRXBMRjh1MTN4U1JrYzJFZVRURmFBNFlXXG5FWkg1aUNKNHU2QnVYUmNlSjBEdVBQeDFaUXM3U2NzMTRhYVY4ZjJ0NHhROVBvbis3Y2pMbWNaM0FFM3FvQkFrXG5WcFBoelNmR0M1YnZLZ1Mzb1JjTFZtTU1ZM1pyMVRLT011VzNuUndsWFE2SUVTeUZBRGNxcUpFeXRqZnFmOEcyXG5FRTN5NzAyYnRRS0JnUUM1QkxteCt1b29lOFVhTjFUYUkwRzlFTzBDYmpHd1pibjFVeVgrZHRqTjUxYkgwZVFoXG5iZFRwQ1VqcmtUWFFVU01aVStjdWpiSFdTYVJSc1h4VDNCd1hJWEhudHY1Mk5oYTlBQ0E2T2c1TkhEUFFuQ1VnXG55eCtzYU1OSTBIVG9wdEVpaGFTN3VudEhVd1h6VWNJWEVkeFI2djdjNlZPUmlkTFVJVytxY1FneFR3S0JnUUNIXG5EdXV2M1R0bWVpcy9UcTdHOVZxdk1rdXV0NDY2cTZ1SXowMkRYYTkzV055RFBWVmhJMXNoRkVucVdXUzNUcDVBXG5UaHZxdE52Y0ZyK1U2WlBPSEtBaVhKTmhuenpQcEhLaWNEbHZqYnN6aC9VeHI5RUwxK1laYlloVXAwZWJuWjFyXG42ZkxCaTJpV1VhUk5PbkkzbUNieURrRWhoRnNiMzVTY2RGZUFWOTJINFFLQmdGYmVFTVNwZy9aLzBEWUFIdjM5XG5qWSs2aXI1ZDNRNUtuOUVjK2pRM3hUdUU1bHpycFpOUytpRUJsSTY1RnN6K25BcHBYc3ZoSk1Vc0xpeHhKL3QyXG5oakxFSkpXR3c0bGVoakU4NFpLOFVOOE1uT0RZcVpvajRna0JkamZ1NEFjVTNuSmd6c1NYMHl2ZXAzcEZWeUxSXG56YXpVTVdoNHRBcW9CQzNYRkxJcTltK0tcbi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS1cbiIsCiAgImNsaWVudF9lbWFpbCI6ICJnY3AtcGlwZWxpbmUtdGVzdEBha2V5bGVzcy10ZXN0LWVudi5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIsCiAgImNsaWVudF9pZCI6ICIxMTE2Mjk5MTg1NTkzMjg5MDEwMTgiLAogICJhdXRoX3VyaSI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20vby9vYXV0aDIvYXV0aCIsCiAgInRva2VuX3VyaSI6ICJodHRwczovL29hdXRoMi5nb29nbGVhcGlzLmNvbS90b2tlbiIsCiAgImF1dGhfcHJvdmlkZXJfeDUwOV9jZXJ0X3VybCI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9vYXV0aDIvdjEvY2VydHMiLAogICJjbGllbnRfeDUwOV9jZXJ0X3VybCI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9yb2JvdC92MS9tZXRhZGF0YS94NTA5L2djcC1waXBlbGluZS10ZXN0JTQwYWtleWxlc3MtdGVzdC1lbnYuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iCn0K"
	GCP_SA_EMAIL     = "gcp-pipeline-test@akeyless-test-env.iam.gserviceaccount.com"
	GCP_TOKEN_SCOPES = "https://www.googleapis.com/auth/cloud-platform"
)

func TestMySqlProducerResource(t *testing.T) {
	name := "mysql_test"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_producer_mysql" "%v" {
			name			= "%v"
			mysql_password	= "password"
			mysql_dbname	= "mysql"
			mysql_host		= "127.0.0.1"
			mysql_port		= "3306"
			mysql_username	= "root"
		}
`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_producer_mysql" "%v" {
			name 					= "%v"
			mysql_password       	= "password"
			mysql_dbname         	= "mysql"
			mysql_host           	= "127.0.0.1"
			mysql_port           	= "3306"
			mysql_username       	= "root"
			secure_access_enable 	= "true"
			secure_access_web    	= "true"
			secure_access_host   	= ["http://jdjfjf.com"]
			tags                 	= ["t1s", "ff32"]
		}
	`, name, itemPath)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestGcpProducerResource(t *testing.T) {
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
			db_name   		= "mysql"
			user_name 		= "root"
			pwd       		= "password"
		}
		resource "akeyless_rotated_secret" "%v" {
			name 			= "%v"
			target_name 	= "%v"
			rotator_type 	= "target"
			rotated_username = "root"
			rotated_password = "password"
			rotator_creds_type = "use-target-creds"
			key = "acc-kgjr7924orf7__account-def-secrets-key__"
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
			db_name   		= "mysql"
			user_name 		= "root"
			pwd       		= "password"
		}
		resource "akeyless_rotated_secret" "%v" {
			name 			= "%v"
			target_name 	= "%v"
			rotator_type 	= "target"
			rotated_username = "root"
			rotated_password = "password"
			rotator_creds_type = "use-target-creds"
			key = "acc-kgjr7924orf7__account-def-secrets-key__"
			tags 			= ["abc", "def"]
			depends_on = [
    			akeyless_target_db.%v,
  			]
		}
	`, targetName, targetPath, name, itemPath, targetPath, targetName)

	tesItemResource(t, config, configUpdate, itemPath)
}
