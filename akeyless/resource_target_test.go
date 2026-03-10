package akeyless

import (
	"context"
	"fmt"
	"strings"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"
)

var checkTargetDestroyed = func(s *terraform.State) error {
	client := *testAccProvider.Meta().(*providerMeta).client
	token := *testAccProvider.Meta().(*providerMeta).token

	for _, rs := range s.RootModule().Resources {
		if strings.HasPrefix(rs.Type, "akeyless_target") {
			body := akeyless_api.TargetGet{
				Name:  rs.Primary.ID,
				Token: &token,
			}
			_, res, err := client.TargetGet(context.Background()).Body(body).Execute()
			if err == nil {
				return fmt.Errorf("target %s still exists", rs.Primary.ID)
			}
			if res != nil && res.StatusCode != 404 {
				return fmt.Errorf("target %s: unexpected status %d", rs.Primary.ID, res.StatusCode)
			}
		}
	}
	return nil
}

func TestGithubTargetResource(t *testing.T) {
	secretName := "github_test"
	secretPath := testPath("terraform_tests")
	config := fmt.Sprintf(`
		resource "akeyless_target_github" "%v" {
			name 					= "%v"
			github_app_id 			= "1234"
			github_app_private_key 	= "abcd"
			description 			= "aaaa"
			github_base_url 		= "https://api.github.com"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_github" "%v" {
			name 					= "%v"
			github_app_id 			= "5678"
			github_app_private_key 	= "efgh"
			description				= "bbbb"
			github_base_url 		= "https://github.example.com/api/v3"
		}
	`, secretName, secretPath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkTargetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkTargetExistsRemotelyprod(secretPath),
					resource.TestCheckResourceAttr("akeyless_target_github.github_test", "description", "aaaa"),
					resource.TestCheckResourceAttr("akeyless_target_github.github_test", "github_base_url", "https://api.github.com"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkTargetExistsRemotelyprod(secretPath),
					resource.TestCheckResourceAttr("akeyless_target_github.github_test", "description", "bbbb"),
					resource.TestCheckResourceAttr("akeyless_target_github.github_test", "github_base_url", "https://github.example.com/api/v3"),
				),
			},
			{
				ResourceName:            "akeyless_target_github.github_test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"github_app_private_key"},
			},
		},
	})
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
			name 			= "%v"
			access_key_id 	= "XXXXXXX"
  			access_key 		= "rgergetghergerg"
			description 	= "test aws target"
			region 			= "us-west-2"
			session_token 	= "test-session-token"
		}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_aws" "%v" {
			name 			= "%v"
			access_key_id 	= "YYYYYYY"
  			access_key 		= "0I/sdgfvfsgs/sdfrgrfv"
			description 	= "updated aws target"
			region 			= "eu-west-1"
			session_token 	= "test-session-token-updated"
		}
	`, secretName, secretPath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkTargetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkTargetExistsRemotelyprod(secretPath),
					resource.TestCheckResourceAttr("akeyless_target_aws.aws123", "description", "test aws target"),
					resource.TestCheckResourceAttr("akeyless_target_aws.aws123", "region", "us-west-2"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkTargetExistsRemotelyprod(secretPath),
					resource.TestCheckResourceAttr("akeyless_target_aws.aws123", "description", "updated aws target"),
					resource.TestCheckResourceAttr("akeyless_target_aws.aws123", "region", "eu-west-1"),
				),
			},
			{
				ResourceName:            "akeyless_target_aws.aws123",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"access_key", "session_token"},
			},
		},
	})
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
      	}
	`, secretName, secretPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_windows" "%v" {
       		name        = "%v"
       		hostname    = "127.0.0.2"
       		username    = "superadmin"
       		password    = "mypassword"
       		port        = "1000"
       		description = "test my description"
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

	configUpdate2 := fmt.Sprintf(`
		resource "akeyless_target_linked" "%v" {
			name 					= "%v"
			hosts	= "aaa.com;fff,"
			type 		= "mssql"
			description = "bbb"
		}
	`, secretName, secretPath)

	configUpdate3 := fmt.Sprintf(`
		resource "akeyless_target_linked" "%v" {
			name 					= "%v"
			hosts	= "aaa.com;fff,www.test3.com;"
			type 		= "mssql"
			description = "bbb"
		}
	`, secretName, secretPath)

	configUpdate4 := fmt.Sprintf(`
		resource "akeyless_target_linked" "%v" {
			name 					= "%v"
			hosts	= "aaa.com;fff,www.test4"
			type 		= "mssql"
			description = "bbb"
		}
	`, secretName, secretPath)

	configUpdate5 := fmt.Sprintf(`
		resource "akeyless_target_linked" "%v" {
			name 					= "%v"
			hosts	= "aaa.com;fff,www.test4;"
			type 		= "mssql"
			description = "bbb"
		}
	`, secretName, secretPath)

	testTargetResource(t, secretPath, config, configUpdate, configUpdate2, configUpdate3, configUpdate4, configUpdate5)

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

func testTargetResource(t *testing.T, secretPath string, configs ...string) {
	steps := make([]resource.TestStep, len(configs))
	for i, config := range configs {
		steps[i] = resource.TestStep{
			Config: config,
			Check: resource.ComposeTestCheckFunc(
				checkTargetExistsRemotelyprod(secretPath),
			),
		}
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkTargetDestroyed,
		Steps:             steps,
	})
}

func tesTargetResource(t *testing.T, config, configUpdate, secretPath string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkTargetDestroyed,
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

func TestDockerhubTargetResource(t *testing.T) {
	targetName := "dockerhub_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_dockerhub" "%v" {
			name 				= "%v"
			dockerhub_username 	= "testuser"
			dockerhub_password 	= "testpass"
			description 		= "Test Dockerhub target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_dockerhub" "%v" {
			name 				= "%v"
			dockerhub_username 	= "testuser2"
			dockerhub_password 	= "testpass2"
			description 		= "Updated Dockerhub target"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
}

func TestHashivaultTargetResource(t *testing.T) {
	skipIfNoGateway(t)
	t.Parallel()
	targetName := "hashivault_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_hashivault" "%v" {
			name 				= "%v"
			hashi_url 			= "https://vault.example.com"
			vault_token 		= "test-token"
			description 		= "Test Hashivault target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_hashivault" "%v" {
			name 				= "%v"
			hashi_url 			= "https://vault2.example.com"
			vault_token 		= "test-token2"
			description 		= "Updated Hashivault target"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
}

func TestLdapTargetResource(t *testing.T) {
	targetName := "ldap_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_ldap" "%v" {
			name 				= "%v"
			ldap_url 			= "ldap://ldap.example.com"
			bind_dn 			= "cn=admin,dc=example,dc=com"
			bind_dn_password 	= "password"
			description 		= "Test LDAP target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_ldap" "%v" {
			name 				= "%v"
			ldap_url 			= "ldap://ldap2.example.com"
			bind_dn 			= "cn=admin2,dc=example,dc=com"
			bind_dn_password 	= "password2"
			description 		= "Updated LDAP target"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
}

func TestOpenAITargetResource(t *testing.T) {
	skipIfNoGateway(t)
	t.Parallel()
	targetName := "openai_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name 				= "%v"
			api_key 			= "sk-test123"
			description 		= "Test OpenAI target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name 				= "%v"
			api_key 			= "sk-test456"
			description 		= "Updated OpenAI target"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
}

func TestPingTargetResource(t *testing.T) {
	targetName := "ping_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_ping" "%v" {
			name 					= "%v"
			ping_url 				= "https://8.8.8.8"
			administrative_port 	= "9999"
			authorization_port 		= "9031"
			privileged_user 		= "admin"
			password 				= "password"
			description 			= "Test Ping target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_ping" "%v" {
			name 					= "%v"
			ping_url 				= "https://1.1.1.1:443"
			administrative_port 	= "9998"
			authorization_port 		= "9032"
			privileged_user 		= "admin2"
			password 				= "password2"
			description 			= "Updated Ping target"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
}

func TestSalesforceTargetResource(t *testing.T) {
	targetName := "salesforce_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_salesforce" "%v" {
			name 				= "%v"
			auth_flow 			= "user-password"
			client_id 			= "test-client-id"
			client_secret 		= "test-client-secret"
			email 				= "test@example.com"
			tenant_url 			= "https://test.salesforce.com"
			password 			= "password"
			security_token 		= "token"
			description 		= "Test Salesforce target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_salesforce" "%v" {
			name 				= "%v"
			auth_flow 			= "user-password"
			client_id 			= "test-client-id2"
			client_secret 		= "test-client-secret2"
			email 				= "test2@example.com"
			tenant_url 			= "https://test2.salesforce.com"
			password 			= "password2"
			security_token 		= "token2"
			description 		= "Updated Salesforce target"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
}

func TestSectigoTargetResource(t *testing.T) {
	targetName := "sectigo_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_sectigo" "%v" {
			name 				= "%v"
			username 			= "testuser"
			password 			= "testpass"
			customer_uri 		= "https://sectigo.example.com"
			certificate_profile_id = 123
			organization_id 	= 456
			external_requester 	= "test@example.com"
			description 		= "Test Sectigo target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_sectigo" "%v" {
			name 				= "%v"
			username 			= "testuser2"
			password 			= "testpass2"
			customer_uri 		= "https://sectigo2.example.com"
			certificate_profile_id = 789
			organization_id 	= 101112
			external_requester 	= "test2@example.com"
			description 		= "Updated Sectigo target"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
}

func TestGodaddyTargetResource(t *testing.T) {
	targetName := "godaddy_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_godaddy" "%v" {
			name 				= "%v"
			api_key 			= "test-api-key"
			secret 				= "test-api-secret"
			imap_username 		= "imap@example.com"
			imap_password 		= "imap-password"
			imap_fqdn 			= "imap.example.com"
			description 		= "Test GoDaddy target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_godaddy" "%v" {
			name 				= "%v"
			api_key 			= "test-api-key2"
			secret 				= "test-api-secret2"
			imap_username 		= "imap2@example.com"
			imap_password 		= "imap-password2"
			imap_fqdn 			= "imap2.example.com"
			description 		= "Updated GoDaddy target"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
}

func TestGlobalSignAtlasTargetResource(t *testing.T) {
	targetName := "globalsign_atlas_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_globalsign_atlas" "%v" {
			name 				= "%v"
			api_key 			= "test-api-key"
			api_secret 			= "test-api-secret"
			mtls_cert_data_base64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURpekNDQW5PZ0F3SUJBZ0lVVlZMQ2pWV2J0QVdOZnBVb0wwbDNINU80dU5zd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1ZURUxNQWtHQTFVRUJoTUNWVk14RFRBTEJnTlZCQWdNQkZSbGMzUXhEVEFMQmdOVkJBY01CRlJsYzNReApEVEFMQmdOVkJBb01CRlJsYzNReEdUQVhCZ05WQkFNTUVIUmxjM1F1WlhoaGJYQnNaUzVqYjIwd0hoY05Nall3Ck1qQTRNVEl4TmpNMVdoY05NamN3TWpBNE1USXhOak0xV2pCVk1Rc3dDUVlEVlFRR0V3SlZVekVOTUFzR0ExVUUKQ0F3RVZHVnpkREVOTUFzR0ExVUVCd3dFVkdWemRERU5NQXNHQTFVRUNnd0VWR1Z6ZERFWk1CY0dBMVVFQXd3UQpkR1Z6ZEM1bGVHRnRjR3hsTG1OdmJUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCCkFKOEZjZ1N1NmlqV01iSzBKWVlrbTZCVUUvbmFmY3d1R2hYVllLTy9JZEQyMjRSQnI1b2NhbGdYVnFOYXpsR1MKSlFkY3VmdThiNG5Ea3M4QjdKWmVRZFlNMnN2OXFtME5nazNoNVQyVDNwZUZOcUl4bnZLcEZsZm12bUtYcitjNAo1RTlTcXlwdDdvRmd0L2JNc1R4Y2Z5V0lCZVNNNDE4UDczYThrb3pRdWZoRVJRVnl4azFBZzBwSmFRTGZnb01WClJHQnN4bE9pT1QwV1h1SmhZa0hLdmJhMjBjVG94VHhLbHhzR0Z4ODJtVm0xZ29OK3VlUldUTm9mT2FDbHNjcUQKblFLSWR6R2d3ampxL0JzVFJIdGNPUkVJRE5HRVIrOEp1UkNqYnpzMFNYcmcyY3RRU28wdHlDRTROZGtpc1lTOApxZCs5S3hWMG8wT0Q4Y3BUU2trQzdNY0NBd0VBQWFOVE1GRXdIUVlEVlIwT0JCWUVGSm1RT3VJbFgvK0tYRGc4ClpKbjdsRUVxS25Kd01COEdBMVVkSXdRWU1CYUFGSm1RT3VJbFgvK0tYRGc4WkpuN2xFRXFLbkp3TUE4R0ExVWQKRXdFQi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFCdzR6V0xDUWdiQkRBZ2VpbGZWNkVjUwpuRXJ1aGkwMnVmSzVHUUMzZmlDZmdXemhJVlhBdWVQNHU5eXdnR01lc2lGTkpFeHVuUWhIVnFLb2d2bktpbDI1CmVybUIrbDVVN2FWZ2RXS0Y1NDR0bUw2anVhUFN1YXI3M0laT0hVYk4ybmo2dU4zckdyek9RVFJ1clMrZlVWaXAKZk5qUXBzVFJrRUFUOThYSEpxNzdrSnZEcThwcGxuRVRWUldlZ1Naakk0T1hsYVhmVnE2M2NNMXNpR2tvSlpUQwpOaXhrRXJVWVZ6QzZldUZFeXRCR2puSUZSTTUyVFR1c051TVhzclMrRnMxRU5DVnZPV253K1ZuZ0c0a2IxclYxCnRsNUhha1cvV0h4TEdaOWNFUUVRZHhvcFU4NXQxd01JUStiVktoN2hzY2lKUDhBQUtKMGpZSVJsVUhvSEZ4Yz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
			mtls_key_data_base64 = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRQ2ZCWElFcnVvbzFqR3kKdENXR0pKdWdWQlA1Mm4zTUxob1YxV0NqdnlIUTl0dUVRYSthSEdwWUYxYWpXczVSa2lVSFhMbjd2RytKdzVMUApBZXlXWGtIV0ROckwvYXB0RFlKTjRlVTlrOTZYaFRhaU1aN3lxUlpYNXI1aWw2L25PT1JQVXFzcWJlNkJZTGYyCnpMRThYSDhsaUFYa2pPTmZEKzkydkpLTTBMbjRSRVVGY3NaTlFJTktTV2tDMzRLREZVUmdiTVpUb2prOUZsN2kKWVdKQnlyMjJ0dEhFNk1VOFNwY2JCaGNmTnBsWnRZS0Rmcm5rVmt6YUh6bWdwYkhLZzUwQ2lIY3hvTUk0NnZ3YgpFMFI3WERrUkNBelJoRWZ2Q2JrUW8yODdORWw2NE5uTFVFcU5MY2doT0RYWklyR0V2S25mdlNzVmRLTkRnL0hLClUwcEpBdXpIQWdNQkFBRUNnZ0VBRHVjMXZsYWVQMkdEbXRualFtVWY2TEM0aG93QmlpY3Y3cWZtdkxIbSsyeUgKT2lmbHl5MnFrY0x1TGJVTzdQb2pXa05JY3QxQUhzc2pjUjhmQ3lDZVR1ODVlakMxemk2YjdheWtEVmRVWHlMdQo4ZGh3cXhGSnRNYzlSSVF1eWg2ODF1cEtmRmw5SnNibnRzdU1PTG42ZUl2ODhXUjYwcWZ0cTFVVTd2bUkxRWw3CjFNaEczQ2xiNGE2c0JmWlNNeDJYcWdWR1ZiWm5tcndoR3llTDB4Zld6SXhSQkVFdFMxSE9Fc0RiSi9TQWhpN3oKWFZBQWNzMTFZRlBlakMxcWVoQzh5bzdGb2FVUmZVKzVQSENEUTFsc28xT28zdEJyaDBQeTZjMDRWMldKa1NVYgp5VjVwNHZ5K3lUYmFyQzFZaVdrWGE1TnVXK1RwMHk4OUYzNUpweEk5a1FLQmdRREtyZlRGRU1HYm9haDBrMWl5Cm5rUXN0Q1JVWWtHMWVoeTByRkRkZlZVdkRUSmtDV29Hc0crK2txT0EyVDNDMlNvTWFlUzQ5VnRYdzhXUVpCbkQKSHJ4bHFmckVCVmNNRFJtaGlLVldUUWRPZEFzNFBiSDEzKzRXQkdCTlA5QkZ2OWN1UjJadFc0alFTM0doZ2RkNwpCZW5aUkpXRnhMZzB0V0hSY05EVUlhWUVVd0tCZ1FESTJ6Sit3a2UzN3VEbmtsdGY0WDJ6RXJHaGxYdWlwQTlECkNuQ1hxZUdZME9aNmk4NEo5NExDVmVuTkxJK3pTNkg4eksrdjlQeHpUZEQvTGVCdXUvdWRQZVY0ZUVpVXBQa3QKWWtIdHI4TUpRaklXNmFFS1RIdXBKTVBBZ2dYY1JjNEhSbmZ3K2E3bHYxM2lLQnhxK3lFam12UGhza3hTNEIyZApCc0l2UFovblBRS0JnUUN0TzFmZFk4QUhWSG5XQWVhcTdJa2FxSEh3eWZhZHRSeDU5Rm85cFpVOFhRdzM0ckFECnZhUVUvK0xPQzJBMWZVWHFURXdaSm1VSE02WldEcWpTVkIvMHlQOHpzZGkvelNhZUlWd24waml2ZnBIa1pSOEoKSjNlb3k5Ni95QTRzdjVhYzBKd2tWanN1eFh6KzdTcU8xUFFXSnYraDBRMGN4L2N1ZXoyU1FweFNUd0tCZ0RxUApCWnJGUTZtUmdJcWpOZmF2UkRtSU1yZWNZRTVicklOc01NVlc1d25wcGJpR3VBeFoyQXFXaDdLazBrU0F3WHAxCnBxY1RNdUxmQmhiUHBrWkNraW9XMktjVjBudGIyYlhzbHJJWWN6Rm8xamV0NTZDY0NkV1hmV2JMd2ErbHZscUsKcGY5Z25DZ3BjZEsweFF3L3FUcTdPMjFLMFV1OFFZWDlhWEhpY3BNMUFvR0JBTE5TWmY5ZnZxYzFxMVpJU0l6dwpIbUIxaDM3L2F4aE00K3NVM09ZcGZOZUQrdEkxOUJpV0hPa3NINnhESUhRcEtaVUxOSURhNjMzWFF4TlIyeGFXClFEZ3NNQ3dkMzZId1k2dGp3UXNQclJPNFgzbWZobUxyamhTRG9adVBoZUxMMmFlNCtQMnZKSy81VnYrR2ViWk8KcENGTFoxekJPdkpiYnJaRXJwUyt6cVVtCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K"
			description 		= "Test GlobalSign Atlas target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_globalsign_atlas" "%v" {
			name 				= "%v"
			api_key 			= "test-api-key2"
			api_secret 			= "test-api-secret2"
			mtls_cert_data_base64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURpekNDQW5PZ0F3SUJBZ0lVVlZMQ2pWV2J0QVdOZnBVb0wwbDNINU80dU5zd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1ZURUxNQWtHQTFVRUJoTUNWVk14RFRBTEJnTlZCQWdNQkZSbGMzUXhEVEFMQmdOVkJBY01CRlJsYzNReApEVEFMQmdOVkJBb01CRlJsYzNReEdUQVhCZ05WQkFNTUVIUmxjM1F1WlhoaGJYQnNaUzVqYjIwd0hoY05Nall3Ck1qQTRNVEl4TmpNMVdoY05NamN3TWpBNE1USXhOak0xV2pCVk1Rc3dDUVlEVlFRR0V3SlZVekVOTUFzR0ExVUUKQ0F3RVZHVnpkREVOTUFzR0ExVUVCd3dFVkdWemRERU5NQXNHQTFVRUNnd0VWR1Z6ZERFWk1CY0dBMVVFQXd3UQpkR1Z6ZEM1bGVHRnRjR3hsTG1OdmJUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCCkFKOEZjZ1N1NmlqV01iSzBKWVlrbTZCVUUvbmFmY3d1R2hYVllLTy9JZEQyMjRSQnI1b2NhbGdYVnFOYXpsR1MKSlFkY3VmdThiNG5Ea3M4QjdKWmVRZFlNMnN2OXFtME5nazNoNVQyVDNwZUZOcUl4bnZLcEZsZm12bUtYcitjNAo1RTlTcXlwdDdvRmd0L2JNc1R4Y2Z5V0lCZVNNNDE4UDczYThrb3pRdWZoRVJRVnl4azFBZzBwSmFRTGZnb01WClJHQnN4bE9pT1QwV1h1SmhZa0hLdmJhMjBjVG94VHhLbHhzR0Z4ODJtVm0xZ29OK3VlUldUTm9mT2FDbHNjcUQKblFLSWR6R2d3ampxL0JzVFJIdGNPUkVJRE5HRVIrOEp1UkNqYnpzMFNYcmcyY3RRU28wdHlDRTROZGtpc1lTOApxZCs5S3hWMG8wT0Q4Y3BUU2trQzdNY0NBd0VBQWFOVE1GRXdIUVlEVlIwT0JCWUVGSm1RT3VJbFgvK0tYRGc4ClpKbjdsRUVxS25Kd01COEdBMVVkSXdRWU1CYUFGSm1RT3VJbFgvK0tYRGc4WkpuN2xFRXFLbkp3TUE4R0ExVWQKRXdFQi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFCdzR6V0xDUWdiQkRBZ2VpbGZWNkVjUwpuRXJ1aGkwMnVmSzVHUUMzZmlDZmdXemhJVlhBdWVQNHU5eXdnR01lc2lGTkpFeHVuUWhIVnFLb2d2bktpbDI1CmVybUIrbDVVN2FWZ2RXS0Y1NDR0bUw2anVhUFN1YXI3M0laT0hVYk4ybmo2dU4zckdyek9RVFJ1clMrZlVWaXAKZk5qUXBzVFJrRUFUOThYSEpxNzdrSnZEcThwcGxuRVRWUldlZ1Naakk0T1hsYVhmVnE2M2NNMXNpR2tvSlpUQwpOaXhrRXJVWVZ6QzZldUZFeXRCR2puSUZSTTUyVFR1c051TVhzclMrRnMxRU5DVnZPV253K1ZuZ0c0a2IxclYxCnRsNUhha1cvV0h4TEdaOWNFUUVRZHhvcFU4NXQxd01JUStiVktoN2hzY2lKUDhBQUtKMGpZSVJsVUhvSEZ4Yz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
			mtls_key_data_base64 = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRQ2ZCWElFcnVvbzFqR3kKdENXR0pKdWdWQlA1Mm4zTUxob1YxV0NqdnlIUTl0dUVRYSthSEdwWUYxYWpXczVSa2lVSFhMbjd2RytKdzVMUApBZXlXWGtIV0ROckwvYXB0RFlKTjRlVTlrOTZYaFRhaU1aN3lxUlpYNXI1aWw2L25PT1JQVXFzcWJlNkJZTGYyCnpMRThYSDhsaUFYa2pPTmZEKzkydkpLTTBMbjRSRVVGY3NaTlFJTktTV2tDMzRLREZVUmdiTVpUb2prOUZsN2kKWVdKQnlyMjJ0dEhFNk1VOFNwY2JCaGNmTnBsWnRZS0Rmcm5rVmt6YUh6bWdwYkhLZzUwQ2lIY3hvTUk0NnZ3YgpFMFI3WERrUkNBelJoRWZ2Q2JrUW8yODdORWw2NE5uTFVFcU5MY2doT0RYWklyR0V2S25mdlNzVmRLTkRnL0hLClUwcEpBdXpIQWdNQkFBRUNnZ0VBRHVjMXZsYWVQMkdEbXRualFtVWY2TEM0aG93QmlpY3Y3cWZtdkxIbSsyeUgKT2lmbHl5MnFrY0x1TGJVTzdQb2pXa05JY3QxQUhzc2pjUjhmQ3lDZVR1ODVlakMxemk2YjdheWtEVmRVWHlMdQo4ZGh3cXhGSnRNYzlSSVF1eWg2ODF1cEtmRmw5SnNibnRzdU1PTG42ZUl2ODhXUjYwcWZ0cTFVVTd2bUkxRWw3CjFNaEczQ2xiNGE2c0JmWlNNeDJYcWdWR1ZiWm5tcndoR3llTDB4Zld6SXhSQkVFdFMxSE9Fc0RiSi9TQWhpN3oKWFZBQWNzMTFZRlBlakMxcWVoQzh5bzdGb2FVUmZVKzVQSENEUTFsc28xT28zdEJyaDBQeTZjMDRWMldKa1NVYgp5VjVwNHZ5K3lUYmFyQzFZaVdrWGE1TnVXK1RwMHk4OUYzNUpweEk5a1FLQmdRREtyZlRGRU1HYm9haDBrMWl5Cm5rUXN0Q1JVWWtHMWVoeTByRkRkZlZVdkRUSmtDV29Hc0crK2txT0EyVDNDMlNvTWFlUzQ5VnRYdzhXUVpCbkQKSHJ4bHFmckVCVmNNRFJtaGlLVldUUWRPZEFzNFBiSDEzKzRXQkdCTlA5QkZ2OWN1UjJadFc0alFTM0doZ2RkNwpCZW5aUkpXRnhMZzB0V0hSY05EVUlhWUVVd0tCZ1FESTJ6Sit3a2UzN3VEbmtsdGY0WDJ6RXJHaGxYdWlwQTlECkNuQ1hxZUdZME9aNmk4NEo5NExDVmVuTkxJK3pTNkg4eksrdjlQeHpUZEQvTGVCdXUvdWRQZVY0ZUVpVXBQa3QKWWtIdHI4TUpRaklXNmFFS1RIdXBKTVBBZ2dYY1JjNEhSbmZ3K2E3bHYxM2lLQnhxK3lFam12UGhza3hTNEIyZApCc0l2UFovblBRS0JnUUN0TzFmZFk4QUhWSG5XQWVhcTdJa2FxSEh3eWZhZHRSeDU5Rm85cFpVOFhRdzM0ckFECnZhUVUvK0xPQzJBMWZVWHFURXdaSm1VSE02WldEcWpTVkIvMHlQOHpzZGkvelNhZUlWd24waml2ZnBIa1pSOEoKSjNlb3k5Ni95QTRzdjVhYzBKd2tWanN1eFh6KzdTcU8xUFFXSnYraDBRMGN4L2N1ZXoyU1FweFNUd0tCZ0RxUApCWnJGUTZtUmdJcWpOZmF2UkRtSU1yZWNZRTVicklOc01NVlc1d25wcGJpR3VBeFoyQXFXaDdLazBrU0F3WHAxCnBxY1RNdUxmQmhiUHBrWkNraW9XMktjVjBudGIyYlhzbHJJWWN6Rm8xamV0NTZDY0NkV1hmV2JMd2ErbHZscUsKcGY5Z25DZ3BjZEsweFF3L3FUcTdPMjFLMFV1OFFZWDlhWEhpY3BNMUFvR0JBTE5TWmY5ZnZxYzFxMVpJU0l6dwpIbUIxaDM3L2F4aE00K3NVM09ZcGZOZUQrdEkxOUJpV0hPa3NINnhESUhRcEtaVUxOSURhNjMzWFF4TlIyeGFXClFEZ3NNQ3dkMzZId1k2dGp3UXNQclJPNFgzbWZobUxyamhTRG9adVBoZUxMMmFlNCtQMnZKSy81VnYrR2ViWk8KcENGTFoxekJPdkpiYnJaRXJwUyt6cVVtCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K"
			description 		= "Updated GlobalSign Atlas target"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
}

func TestGeminiTargetResource(t *testing.T) {
	targetName := "gemini_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_gemini" "%v" {
			name 				= "%v"
			api_key 			= "test-api-key"
			description 		= "Test Gemini target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_gemini" "%v" {
			name 				= "%v"
			api_key 			= "test-api-key2"
			description 		= "Updated Gemini target"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
}

func TestRabbitmqTargetResource(t *testing.T) {
	targetName := "rabbitmq_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_rabbit" "%v" {
			name 				= "%v"
			rabbitmq_server_uri = "amqp://localhost:5672"
			rabbitmq_server_user = "guest"
			rabbitmq_server_password = "guest"
			description 		= "Test RabbitMQ target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_rabbit" "%v" {
			name 				= "%v"
			rabbitmq_server_uri = "amqp://localhost:5673"
			rabbitmq_server_user = "admin"
			rabbitmq_server_password = "admin"
			description 		= "Updated RabbitMQ target"
		}
	`, targetName, targetPath)

	tesTargetResource(t, config, configUpdate, targetPath)
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
