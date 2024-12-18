package akeyless

import (
	"context"
	"fmt"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"
)

func TestGithubTargetResource(t *testing.T) {
	secretName := "github_test"
	secretPath := testPath("terraform_tests")
	config := fmt.Sprintf(`
		resource "akeyless_target_github" "%v" {
			name 					= "%v"
			github_app_id 			= "1234"
			github_app_private_key 	= "abcd"
			description 			= "aaaa"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_github" "%v" {
			name 					= "%v"
			github_app_id 			= "5678"
			github_app_private_key 	= "efgh"
			description				= "bbbb"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestGitlabTargetResource(t *testing.T) {
	secretName := "gitlab_test"
	secretPath := testPath("gitlab_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_gitlab" "%v" {
			name 				= "%v"
			gitlab_access_token = "aaaaa"
			gitlab_certificate  = "1234"
			description 		= "eeeee"
			gitlab_url 			= "https:aaaaa.com"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_gitlab" "%v" {
			name 				= "%v"
			gitlab_access_token = "bbbbb"
  			gitlab_certificate  = "5678"
			description			= "ddddd"
		}
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
			description 	= "fkfmkfm"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)

}

func TestWebTargetResource(t *testing.T) {
	secretName := "web123"
	secretPath := testPath("web_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_web" "%v" {
			name 		= "%v"
			url     	= "dfcefkmk"
			description = "rgergetghergerg"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_web" "%v" {
			name 		= "%v"
			url     	= "YYYYYYY"
			description = "0I/sdgfvfsgs/sdfrgrfv"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestWindowsTargetResource(t *testing.T) {
	secretName := "windows123"
	secretPath := testPath("windows_target1")
	config := fmt.Sprintf(`
		resource "akeyless_target_windows" "%v" {
       		name        = "%v"
       		hostname    = "127.0.0.1"
       		username    = "admin"
       		password    = "password"
       		domain      = "domain"
       		port        = "5986"
       		max_versions = "5"
      	}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_windows" "%v" {
       		name        = "%v"
       		hostname    = "127.0.0.2"
       		username    = "superadmin"
       		password    = "mypassword"
       		domain      = "mydomain"
       		port        = "1000"
       		description = "test my description"
       		max_versions = "10"
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
	secretName := "artifactory-target"
	secretPath := testPath(secretName)

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
	secretName := "gcp-target"
	secretPath := testPath(secretName)

	config := fmt.Sprintf(`
		resource "akeyless_target_gcp" "%v" {
			name 			= "%v"
			gcp_sa_email	= "a@a.aa"
			gcp_key 		= "YmxhYmxh"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_gcp" "%v" {
			name 			= "%v"
			gcp_sa_email	= "b@b.bb"
			gcp_key 		= "YmxpYmxp"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestGkeTargetResource(t *testing.T) {
	secretName := "gke-target"
	secretPath := testPath(secretName)

	config := fmt.Sprintf(`
		resource "akeyless_target_gke" "%v" {
			name = "%v"
			gke_service_account_email	= "a@a.aa"
			gke_cluster_endpoint 		= "https://akaka.com"
			gke_cluster_cert 			= "YmxhYmxh"
			gke_account_key 			= "YmxhYmxh"
			gke_cluster_name 			= "aaaa"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_gke" "%v" {
			name = "%v"
			gke_service_account_email	= "b@b.bb"
			gke_cluster_endpoint 		= "https://akakad.com"
			gke_cluster_cert 			= "YmxpYmxp"
			gke_account_key 			= "YmxpYmxp"
			gke_cluster_name 			= "bbbb"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestK8sTargetResource(t *testing.T) {
	secretName := "k8s-target"
	secretPath := testPath(secretName)

	config := fmt.Sprintf(`
		resource "akeyless_target_k8s" "%v" {
			name 					= "%v"
			k8s_cluster_endpoint	= "https://www.test1.com"
			k8s_cluster_ca_cert 	= "YmxhYmxh"
			k8s_cluster_token 		= "YmxhYmxh"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_k8s" "%v" {
			name 					= "%v"
			k8s_cluster_endpoint 	= "https://akakad.com"
			k8s_cluster_ca_cert 	= "YmxpYmxp"
			k8s_cluster_token 		= "YmxpYmxp"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)

}

func TestLinkedTargetResource(t *testing.T) {
	secretName := "linked-target"
	secretPath := testPath(secretName)

	config := fmt.Sprintf(`
		resource "akeyless_target_linked" "%v" {
			name 					= "%v"
			hosts	= "www.test1.com;test,aaa.com;fff"
			type 		= "mysql"
			description = "aaa"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_linked" "%v" {
			name 					= "%v"
			hosts	= "aaa.com;fff,www.test1.com;test"
			type 		= "mssql"
			description = "bbb"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)

}

func TestDbTargetResource(t *testing.T) {
	secretName := "db_target1"
	secretPath := testPath(secretName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 		= "%v"
			db_type     = "mysql"
			user_name 	= "user1"
			pwd 		= "pwd1"
			host 		= "host1"
			port 		= "1231"
			db_name 	= "db1"
			description = "aaa"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 		= "%v"
			db_type     = "mysql"
			user_name 	= "user2"
			pwd 		= "pwd2"
			host		= "host2"
			port 		= "1231"
			db_name 	= "db2"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestDbOracleTargetResource(t *testing.T) {
	secretName := "db_target1"
	secretPath := testPath(secretName)

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 				= "%v"
			db_type     		= "oracle"
			user_name 			= "user1"
			pwd 				= "pwd1"
			host 				= "host1"
			port 				= "1231"
			oracle_service_name	= "db1"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 				= "%v"
			db_type     		= "oracle"
			user_name 			= "user2"
			pwd 				= "pwd2"
			host				= "host2"
			port 				= "1231"
			oracle_service_name = "db2"
		}
	`, secretName, secretPath)

	tesTargetResource(t, config, configUpdate, secretPath)
}

func TestEksTargetResource(t *testing.T) {
	secretName := "eks-target"
	secretPath := testPath(secretName)

	config := fmt.Sprintf(`
		resource "akeyless_target_eks" "%v" {
			name 					= "%v"
			eks_cluster_name     	= "aaaa1"
			eks_cluster_endpoint 	= "https://www.test1.com"
			eks_cluster_ca_cert 	= "YmxhYmxh"
			eks_access_key_id 		= "bbbb1"
			eks_secret_access_key	= "cccc1"
		}
	`, secretName, secretPath)

	// configUpdate := fmt.Sprintf(`
	// 	resource "akeyless_target_eks" "%v" {
	// 		name 					= "%v"
	// 		eks_cluster_name     	= "aaaa2"
	// 		eks_cluster_endpoint 	= "https://www.test2.com"
	// 		eks_cluster_ca_cert 	= "YmxpYmxp"
	// 		eks_access_key_id 		= "bbbb2"
	// 		eks_secret_access_key 	= "cccc2"
	// 	}
	// `, secretName, secretPath)

	tesTargetResource(t, config, config, secretPath)
}

func TestZeroSslTargetResource(t *testing.T) {
	targetName := "zerossl_target1"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_zerossl" "%v" {
			name              	= "%v"
			api_key           	= "api_key1"
			timeout           	= "1m0s"
			imap_username     	= "user1"
			imap_password     	= "pass1"
			imap_fqdn         	= "fqdn1"
			imap_target_email	= "ku@ku1.io"
			description       	= "desc1"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_zerossl" "%v" {
			name              	= "%v"
			api_key           	= "api_key2"
			timeout           	= "2m30s"
			imap_username     	= "user2"
			imap_password     	= "pass2"
			imap_fqdn         	= "fqdn2"
			imap_target_email	= "ku@ku2.io"
			description       	= "desc2"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
}

func TestGlobalSignTargetResource(t *testing.T) {
	targetName := "globalsign_target1"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_globalsign" "%v" {
			name              	= "%v"
			timeout             = "1m0s"
			username            = "user1"
			password            = "pass1"
			profile_id          = "id1"
			contact_first_name  = "first1"
			contact_last_name   = "last1"
			contact_phone       = "phone1"
			contact_email		= "ku@ku1.io"
			description       	= "desc1"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_globalsign" "%v" {
			name              	= "%v"
			timeout             = "2m30s"
			username            = "user2"
			password            = "pass2"
			profile_id          = "id2"
			contact_first_name  = "first2"
			contact_last_name   = "last2"
			contact_phone       = "phone2"
			contact_email		= "ku@ku2.io"
			description       	= "desc2"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
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
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		gsvBody := akeyless_api.TargetGet{
			Name:  path,
			Token: &token,
		}

		_, _, err := client.TargetGet(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}

		return nil
	}
}

func deleteTarget(t *testing.T, name string) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	gsvBody := akeyless_api.DeleteTarget{
		Name:  name,
		Token: &token,
	}

	client.DeleteTarget(context.Background()).Body(gsvBody).Execute()
}
