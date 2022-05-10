package akeyless

import (
	"context"
	"fmt"
	"testing"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestGithubTargetResource(t *testing.T) {
	secretName := "github_test"
	secretPath := testPath("terraform_tests")
	config := fmt.Sprintf(`
		resource "akeyless_target_github" "%v" {
			name 					= "%v"
			github_app_id 			= "1234"
			github_app_private_key 	= "abcd"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_github" "%v" {
			name 					= "%v"
			github_app_id 			= "5678"
			github_app_private_key 	= "efgh"
			comment 				= "bla bla"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestDockerhubTargetResource(t *testing.T) {
	secretName := "dockerhub_test"
	secretPath := testPath("terraform_tests")
	config := fmt.Sprintf(`
		resource "akeyless_target_dockerhub" "%v" {
			name 				= "%v"
			dockerhub_username 	= "1234"
			dockerhub_password 	= "abcd"
		}
		`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_dockerhub" "%v" {
			name 				= "%v"
			dockerhub_username 	= "5678"
			dockerhub_password 	= "efgh"
			comment 			= "bla bla"
		`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestAwsTargetResource(t *testing.T) {
	secretName := "aws123"
	secretPath := testPath("aws_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_aws" "%v" {
			name = "%v"
			access_key_id     = "XXXXXXX"
  			access_key = "rgergetghergerg"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_aws" "%v" {
			name = "%v"
			access_key_id     = "YYYYYYY"
  			access_key = "0I/sdgfvfsgs/sdfrgrfv"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestAzureTargetResource(t *testing.T) {
	secretName := "Azure123"
	secretPath := testPath("Azure_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_azure" "%v" {
			name = "%v"
			client_id     = "dcdcdc"
			tenant_id = "rgergetghergerg" 
			client_secret = "dmkdcnkdc"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_azure" "%v" {
			name = "%v"
			client_id     = "dcdcddfrfc"
			tenant_id = "rgergetgheergerg" 
			client_secret = "dmkdcnkdc"
			comment = "fkfmkfm"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)

}

func TestWebTargetResource(t *testing.T) {
	secretName := "web123"
	secretPath := testPath("web_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_web" "%v" {
			name = "%v"
			url     = "dfcefkmk"
  			comment = "rgergetghergerg"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_web" "%v" {
			name = "%v"
			url     = "YYYYYYY"
  			comment = "0I/sdgfvfsgs/sdfrgrfv"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestSSHTargetResource(t *testing.T) {
	secretName := "ssh123"
	secretPath := testPath("ssh_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_ssh" "%v" {
			name = "%v"
			host     = "XXXXXXX"
			port = "22"
			ssh_username = "fff"
			ssh_password = "dddd"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_ssh" "%v" {
			name = "%v"
			host  = "YYYYYYY"
			port = "23"
			ssh_username = "fff"
			ssh_password = "dddd"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestArtifactoryTargetResource(t *testing.T) {
	secretName := "artifactory123"
	secretPath := testPath("artifactory_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_artifactory" "%v" {
			name = "%v"
			base_url     = "XXXXXXX"
			artifactory_admin_name = "rgergetghergerg"
			artifactory_admin_pwd = "ddddd"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_artifactory" "%v" {
			name = "%v"
			base_url     = "dfffff"
			artifactory_admin_name = "rgergddetghergerg"
			artifactory_admin_pwd = "ddddd"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)

}

func TestGcpTargetResource(t *testing.T) {
	secretName := "gcp123"
	secretPath := testPath("gcp_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_gcp" "%v" {
			name = "%v"
			gcp_sa_email     = "XXXXXXX"
			gcp_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KmDcjfruwSq6o5M8+Y3uiWpfNIU71KOWp19i/wWvPbmWgH8MzE+OECzI6Kh1Rp+x4ASDDHg3aDyUSUpGJoX9YvldyPISnp76J2HSlgMri+QQnae5JKC4mzTEdsNXbrw3hZceWuge22/yo4YfPbXmRl5S6Xam/etUqmxYCqUVR98gxu8tTPJAON3Ieg10lmw8DqL41V0+rScwAAacHed6RZzCCqegqmuX0Bqtt2zvwxCoQwS9rk62CrsySfsb1U/1CBzjRKULGCxOT1lVHLqX/IjpGPsgQZZAn0BfxNa/snhTgyp7LXFhBY5iVcMD0KwHy6PqVwdRQ1hZGW/xjidXwIDAQAB"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_gcp" "%v" {
			name = "%v"
			gcp_sa_email     = "YYYYYYY"
			gcp_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KmDcjfruwSq6o5M8+Y3uiWpfNIU71KOWp19i/wWvPbmWgH8MzE+OECzI6Kh1Rp+x4ASDDHg3aDyUSUpGJoX9YvldyPISnp76J2HSlgMri+QQnae5JKC4mzTEdsNXbrw3hZceWuge22/yo4YfPbXmRl5S6Xam/etUqmxYCqUVR98gxu8tTPJAON3Ieg10lmw8DqL41V0+rScwAAacHed6RZzCCqegqmuX0Bqtt2zvwxCoQwS9rk62CrsySfsb1U/1CBzjRKULGCxOT1lVHLqX/IjpGPsgQZZAn0BfxNa/snhTgyp7LXFhBY5iVcMD0KwHy6PqVwdRQ1hZGW/xjidXwIDAQAB"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)

}

func TestGkeTargetResource(t *testing.T) {
	secretName := "gke123"
	secretPath := testPath("gke_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_gke" "%v" {
			name = "%v"
			gke_service_account_email     = "XXXXXXX"
			gke_cluster_endpoint = "https://akaka.com"
			gke_cluster_cert = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KmDcjfruwSq6o5M8+Y3uiWpfNIU71KOWp19i/wWvPbmWgH8MzE+OECzI6Kh1Rp+x4ASDDHg3aDyUSUpGJoX9YvldyPISnp76J2HSlgMri+QQnae5JKC4mzTEdsNXbrw3hZceWuge22/yo4YfPbXmRl5S6Xam/etUqmxYCqUVR98gxu8tTPJAON3Ieg10lmw8DqL41V0+rScwAAacHed6RZzCCqegqmuX0Bqtt2zvwxCoQwS9rk62CrsySfsb1U/1CBzjRKULGCxOT1lVHLqX/IjpGPsgQZZAn0BfxNa/snhTgyp7LXFhBY5iVcMD0KwHy6PqVwdRQ1hZGW/xjidXwIDAQAB"
			gke_account_key = "qwdwd"
			gke_cluster_name = "dddd"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_gke" "%v" {
			name = "%v"
			gke_service_account_email     = "XXXXXXX2"
			gke_cluster_endpoint = "https://akakad.com"
			gke_cluster_cert = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KmDcjfruwSq6o5M8+Y3uiWpfNIU71KOWp19i/wWvPbmWgH8MzE+OECzI6Kh1Rp+x4ASDDHg3aDyUSUpGJoX9YvldyPISnp76J2HSlgMri+QQnae5JKC4mzTEdsNXbrw3hZceWuge22/yo4YfPbXmRl5S6Xam/etUqmxYCqUVR98gxu8tTPJAON3Ieg10lmw8DqL41V0+rScwAAacHed6RZzCCqegqmuX0Bqtt2zvwxCoQwS9rk62CrsySfsb1U/1CBzjRKULGCxOT1lVHLqX/IjpGPsgQZZAn0BfxNa/snhTgyp7LXFhBY5iVcMD0KwHy6PqVwdRQ1hZGW/xjidXwIDAQAB"
			gke_account_key = "qwdwd"
			gke_cluster_name = "dddd"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestK8sTargetResource(t *testing.T) {
	secretName := "k8s123"
	secretPath := testPath("k8s_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_k8s" "%v" {
			name = "%v"
			k8s_cluster_endpoint     = "https://akakad.com"
			k8s_cluster_ca_cert = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KmDcjfruwSq6o5M8+Y3uiWpfNIU71KOWp19i/wWvPbmWgH8MzE+OECzI6Kh1Rp+x4ASDDHg3aDyUSUpGJoX9YvldyPISnp76J2HSlgMri+QQnae5JKC4mzTEdsNXbrw3hZceWuge22/yo4YfPbXmRl5S6Xam/etUqmxYCqUVR98gxu8tTPJAON3Ieg10lmw8DqL41V0+rScwAAacHed6RZzCCqegqmuX0Bqtt2zvwxCoQwS9rk62CrsySfsb1U/1CBzjRKULGCxOT1lVHLqX/IjpGPsgQZZAn0BfxNa/snhTgyp7LXFhBY5iVcMD0KwHy6PqVwdRQ1hZGW/xjidXwIDAQAB"
			  k8s_cluster_token = "djsdkjdkjdhcj"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_k8s" "%v" {
			name = "%v"
			k8s_cluster_endpoint     = "https://akakad.com"
			k8s_cluster_ca_cert = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KmDcjfruwSq6o5M8+Y3uiWpfNIU71KOWp19i/wWvPbmWgH8MzE+OECzI6Kh1Rp+x4ASDDHg3aDyUSUpGJoX9YvldyPISnp76J2HSlgMri+QQnae5JKC4mzTEdsNXbrw3hZceWuge22/yo4YfPbXmRl5S6Xam/etUqmxYCqUVR98gxu8tTPJAON3Ieg10lmw8DqL41V0+rScwAAacHed6RZzCCqegqmuX0Bqtt2zvwxCoQwS9rk62CrsySfsb1U/1CBzjRKULGCxOT1lVHLqX/IjpGPsgQZZAn0BfxNa/snhTgyp7LXFhBY5iVcMD0KwHy6PqVwdRQ1hZGW/xjidXwIDAQAB"
			  k8s_cluster_token = "djsdkjdkjdhcjs"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)

}

func TestDbTargetResource(t *testing.T) {
	secretName := "Db123"
	secretPath := testPath("db_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name = "%v"
			db_type     = "mysql"
			  user_name = "rgergetghergerg"
			  host = "ssss"
			  port = "1231"
			  db_name = "mddd"
			  pwd = "ddkdkd"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name = "%v"
			db_type     = "mysql"
			  user_name = "dddd"
			  host = "dddd"
			  port = "1231"
			  db_name = "mdddddd"
			  pwd = "ddkdkd"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestEksTargetResource(t *testing.T) {
	secretName := "eks123"
	secretPath := testPath("eks_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_eks" "%v" {
			name = "%v"
			eks_cluster_name     = "XXXXXXX"
			eks_cluster_endpoint = "https://jjjj.com"
			eks_cluster_ca_cert = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KmDcjfruwSq6o5M8+Y3uiWpfNIU71KOWp19i/wWvPbmWgH8MzE+OECzI6Kh1Rp+x4ASDDHg3aDyUSUpGJoX9YvldyPISnp76J2HSlgMri+QQnae5JKC4mzTEdsNXbrw3hZceWuge22/yo4YfPbXmRl5S6Xam/etUqmxYCqUVR98gxu8tTPJAON3Ieg10lmw8DqL41V0+rScwAAacHed6RZzCCqegqmuX0Bqtt2zvwxCoQwS9rk62CrsySfsb1U/1CBzjRKULGCxOT1lVHLqX/IjpGPsgQZZAn0BfxNa/snhTgyp7LXFhBY5iVcMD0KwHy6PqVwdRQ1hZGW/xjidXwIDAQAB"
			eks_access_key_id = "eks_access_key_id"
			eks_secret_access_key = "ddjdjdj"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_eks" "%v" {
			name = "%v"
			eks_cluster_name     = "XXXXXXX"
			eks_cluster_endpoint = "https://jjjj.com"
			eks_cluster_ca_cert = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KmDcjfruwSq6o5M8+Y3uiWpfNIU71KOWp19i/wWvPbmWgH8MzE+OECzI6Kh1Rp+x4ASDDHg3aDyUSUpGJoX9YvldyPISnp76J2HSlgMri+QQnae5JKC4mzTEdsNXbrw3hZceWuge22/yo4YfPbXmRl5S6Xam/etUqmxYCqUVR98gxu8tTPJAON3Ieg10lmw8DqL41V0+rScwAAacHed6RZzCCqegqmuX0Bqtt2zvwxCoQwS9rk62CrsySfsb1U/1CBzjRKULGCxOT1lVHLqX/IjpGPsgQZZAn0BfxNa/snhTgyp7LXFhBY5iVcMD0KwHy6PqVwdRQ1hZGW/xjidXwIDAQAB"
			eks_access_key_id = "eks_access_key_id"
			eks_secret_access_key = "ddjdjdj"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func tesTargetResource(t *testing.T, config, configUpdate, secretPath string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkTargetExistsRemotelyprod(secretPath),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkTargetExistsRemotelyprod(secretPath),
				),
			},
		},
	})
}

func checkTargetExistsRemotelyprod(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GetTarget{
			Name:  path,
			Token: &token,
		}

		_, _, err := client.GetTarget(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}

		return nil
	}
}
