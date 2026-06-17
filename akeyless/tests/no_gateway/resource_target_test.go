package no_gateway

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestTargetArtifactoryResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, secretPath)
}

func TestTargetAwsResource(t *testing.T) {
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
		CheckDestroy:      testutils.CheckTargetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(secretPath),
					resource.TestCheckResourceAttr("akeyless_target_aws.aws123", "description", "test aws target"),
					resource.TestCheckResourceAttr("akeyless_target_aws.aws123", "region", "us-west-2"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(secretPath),
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

func TestTargetAzureResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, secretPath)

}

func TestTargetDbResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, secretPath)
}

func TestTargetDbMTLSResource(t *testing.T) {
	secretName := "db_target_mtls"
	secretPath := testPath(secretName)

	clientCert1 := base64.StdEncoding.EncodeToString([]byte("client-cert-1"))
	clientKey1 := base64.StdEncoding.EncodeToString([]byte("client-key-1"))
	clientCert2 := base64.StdEncoding.EncodeToString([]byte("client-cert-2"))
	clientKey2 := base64.StdEncoding.EncodeToString([]byte("client-key-2"))

	config := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 				= "%v"
			db_type     		= "mysql"
			user_name 			= "user1"
			pwd 				= "pwd1"
			host 				= "host1"
			port 				= "1231"
			db_name 			= "db1"
			ssl 				= true
			enable_mtls 		= true
			client_certificate 	= "%v"
			client_private_key 	= "%v"
			client_key_passphrase = "client-pass-1"
		}
	`, secretName, secretPath, clientCert1, clientKey1)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_db" "%v" {
			name 				= "%v"
			db_type     		= "mysql"
			user_name 			= "user2"
			pwd 				= "pwd2"
			host 				= "host2"
			port 				= "1231"
			db_name 			= "db2"
			ssl 				= true
			enable_mtls 		= true
			client_certificate 	= "%v"
			client_private_key 	= "%v"
			client_key_passphrase = "client-pass-2"
		}
	`, secretName, secretPath, clientCert2, clientKey2)
	resourceName := "akeyless_target_db." + secretName
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      testutils.CheckTargetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(secretPath),
					resource.TestCheckResourceAttr(resourceName, "enable_mtls", "true"),
					resource.TestCheckResourceAttr(resourceName, "client_certificate", clientCert1),
					resource.TestCheckResourceAttr(resourceName, "client_private_key", clientKey1),
					resource.TestCheckResourceAttr(resourceName, "client_key_passphrase", "client-pass-1"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(secretPath),
					resource.TestCheckResourceAttr(resourceName, "enable_mtls", "true"),
					resource.TestCheckResourceAttr(resourceName, "client_certificate", clientCert2),
					resource.TestCheckResourceAttr(resourceName, "client_private_key", clientKey2),
					resource.TestCheckResourceAttr(resourceName, "client_key_passphrase", "client-pass-2"),
				),
			},
		},
	})
}

func TestTargetDbOracleResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, secretPath)
}

func TestTargetDockerhubResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetEksResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, config, secretPath)
}

func TestTargetGcpResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, secretPath)
}

func TestTargetGeminiResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetGithubResource(t *testing.T) {
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
		CheckDestroy:      testutils.CheckTargetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(secretPath),
					resource.TestCheckResourceAttr("akeyless_target_github.github_test", "description", "aaaa"),
					resource.TestCheckResourceAttr("akeyless_target_github.github_test", "github_base_url", "https://api.github.com"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(secretPath),
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

func TestTargetGitlabResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, secretPath)
}

func TestTargetGkeResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, secretPath)
}

func TestTargetGlobalSignResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetGlobalSignAtlasResource(t *testing.T) {
	targetName := "globalsign_atlas_target"
	targetPath := testPath(targetName)

	testCert, testKey := testutils.GenerateSelfSignedCertBase64(t)

	config := fmt.Sprintf(`
		resource "akeyless_target_globalsign_atlas" "%v" {
			name 				= "%v"
			api_key 			= "test-api-key"
			api_secret 			= "test-api-secret"
			mtls_cert_data_base64 = "%v"
			mtls_key_data_base64 = "%v"
			description 		= "Test GlobalSign Atlas target"
		}
	`, targetName, targetPath, testCert, testKey)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_globalsign_atlas" "%v" {
			name 				= "%v"
			api_key 			= "test-api-key2"
			api_secret 			= "test-api-secret2"
			mtls_cert_data_base64 = "%v"
			mtls_key_data_base64 = "%v"
			description 		= "Updated GlobalSign Atlas target"
		}
	`, targetName, targetPath, testCert, testKey)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetGodaddyResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetGoogleTrustResource(t *testing.T) {
	eabKeyId := os.Getenv("AKEYLESS_EAB_KEY_ID")
	eabHmacKey := os.Getenv("AKEYLESS_EAB_HMAC_KEY")
	if eabKeyId == "" || eabHmacKey == "" {
		t.Skip("skipping: AKEYLESS_EAB_KEY_ID and AKEYLESS_EAB_HMAC_KEY must be set for Google Trust target tests")
	}

	dnsTargetName := "dns_target"
	dnsTargetPath := testPath(dnsTargetName)
	dnsTargetDetailsType := "aws_target_details"

	expect := map[string]any{
		"access_key_id": "test",
		"access_key":    "test",
		"region":        "us-east-1",
	}

	testutils.CreateTargetByType(t, dnsTargetPath, dnsTargetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, dnsTargetPath)
	})

	targetName := "google_trust_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_google_trust" "%v" {
			name 				= "%v"
			email 				= "test@example.com"
			eab_key_id 			= "%v"
			eab_hmac_key 		= "%v"
			dns_target_creds 	= "%v"
			hosted_zone 		= "Z1234567890"
			google_trust_url 	= "staging"
			timeout 			= "5m"
			description 		= "Test Google Trust target"
		}
	`, targetName, targetPath, eabKeyId, eabHmacKey, dnsTargetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_google_trust" "%v" {
			name 				= "%v"
			email 				= "updated@example.com"
			eab_key_id 			= "%v"
			eab_hmac_key 		= "%v"
			dns_target_creds 	= "%v"
			hosted_zone 		= "Z0987654321"
			google_trust_url 	= "production"
			timeout 			= "10m"
			description 		= "Updated Google Trust target"
		}
	`, targetName, targetPath, eabKeyId, eabHmacKey, dnsTargetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetGoogleTrustResourceCloudflareDnsZone(t *testing.T) {
	eabKeyId := os.Getenv("AKEYLESS_EAB_KEY_ID")
	eabHmacKey := os.Getenv("AKEYLESS_EAB_HMAC_KEY")
	if eabKeyId == "" || eabHmacKey == "" {
		t.Skip("skipping: AKEYLESS_EAB_KEY_ID and AKEYLESS_EAB_HMAC_KEY must be set for Google Trust target tests")
	}

	cfTargetName := "google_trust_cf_dns_target"
	cfTargetPath := testPath(cfTargetName)
	targetName := "google_trust_target_cf"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_cloudflare" "%v" {
			name        = "%v"
			account_id  = "test-account-id"
			api_token   = "test-api-token"
		}

		resource "akeyless_target_google_trust" "%v" {
			name 				= "%v"
			email 				= "test@example.com"
			eab_key_id 			= "%v"
			eab_hmac_key 		= "%v"
			dns_target_creds 	= akeyless_target_cloudflare.%v.name
			dns_zone 			= "cf-zone-123"
			google_trust_url 	= "staging"
			timeout 			= "5m"
			description 		= "Test Google Trust target"
		}
	`, cfTargetName, cfTargetPath, targetName, targetPath, eabKeyId, eabHmacKey, cfTargetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_cloudflare" "%v" {
			name        = "%v"
			account_id  = "test-account-id"
			api_token   = "test-api-token"
		}

		resource "akeyless_target_google_trust" "%v" {
			name 				= "%v"
			email 				= "updated@example.com"
			eab_key_id 			= "%v"
			eab_hmac_key 		= "%v"
			dns_target_creds 	= akeyless_target_cloudflare.%v.name
			dns_zone 			= "cf-zone-456"
			google_trust_url 	= "production"
			timeout 			= "10m"
			description 		= "Updated Google Trust target"
		}
	`, cfTargetName, cfTargetPath, targetName, targetPath, eabKeyId, eabHmacKey, cfTargetName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      testutils.CheckTargetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(targetPath),
					resource.TestCheckResourceAttr(targetPath, "dns_zone", "cf-zone-123"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(targetPath),
					resource.TestCheckResourceAttr(targetPath, "dns_zone", "cf-zone-456"),
				),
			},
		},
	})
}

func TestTargetCloudflareResource(t *testing.T) {
	targetName := "cloudflare_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_cloudflare" "%v" {
			name 				= "%v"
			account_id 			= "test-account-id"
			api_token 			= "test-api-token"
			description 		= "Test Cloudflare target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_cloudflare" "%v" {
			name 				= "%v"
			account_id 			= "test-account-id-2"
			api_token 			= "test-api-token-2"
			description 		= "Updated Cloudflare target"
		}
	`, targetName, targetPath)
	resourceName := "akeyless_target_cloudflare." + targetName
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      testutils.CheckTargetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(targetPath),
					resource.TestCheckResourceAttr(resourceName, "account_id", "test-account-id"),
					resource.TestCheckResourceAttr(resourceName, "api_token", "test-api-token"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(targetPath),
					resource.TestCheckResourceAttr(resourceName, "account_id", "test-account-id-2"),
					resource.TestCheckResourceAttr(resourceName, "api_token", "test-api-token-2"),
				),
			},
		},
	})
}

func TestTargetK8sResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, secretPath)

}

func TestTargetLdapResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetLetsEncryptResource(t *testing.T) {
	dnsTargetName := "dns_target"
	dnsTargetPath := testPath(dnsTargetName)
	dnsTargetDetailsType := "aws_target_details"

	expect := map[string]any{
		"access_key_id": "test",
		"access_key":    "test",
		"region":        "us-east-1",
	}

	testutils.CreateTargetByType(t, dnsTargetPath, dnsTargetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, dnsTargetPath)
	})

	targetName := "lets_encrypt_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_lets_encrypt" "%v" {
			name 				= "%v"
			email 				= "test@example.com"
			dns_target_creds 	= "%v"
			lets_encrypt_url 	= "staging"
			timeout 			= "5m"
			description 		= "Test Lets Encrypt target"
		}
	`, targetName, targetPath, dnsTargetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_lets_encrypt" "%v" {
			name 				= "%v"
			email 				= "updated@example.com"
			dns_target_creds 	= "%v"
			lets_encrypt_url 	= "production"
			timeout 			= "10m"
			description 		= "Updated Lets Encrypt target"
		}
	`, targetName, targetPath, dnsTargetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetLetsEncryptResourceCloudflareDnsZone(t *testing.T) {
	cfTargetName := "lets_encrypt_cf_dns_target"
	cfTargetPath := testPath(cfTargetName)
	targetName := "lets_encrypt_target_cf"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_cloudflare" "%v" {
			name        = "%v"
			account_id  = "test-account-id"
			api_token   = "test-api-token"
		}

		resource "akeyless_target_lets_encrypt" "%v" {
			name 				= "%v"
			email 				= "test@example.com"
			dns_target_creds 	= akeyless_target_cloudflare.%v.name
			dns_zone 			= "cf-zone-123"
			lets_encrypt_url 	= "staging"
			timeout 			= "5m"
			description 		= "Test Lets Encrypt target"
		}
	`, cfTargetName, cfTargetPath, targetName, targetPath, cfTargetName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_cloudflare" "%v" {
			name        = "%v"
			account_id  = "test-account-id"
			api_token   = "test-api-token"
		}

		resource "akeyless_target_lets_encrypt" "%v" {
			name 				= "%v"
			email 				= "updated@example.com"
			dns_target_creds 	= akeyless_target_cloudflare.%v.name
			dns_zone 			= "cf-zone-456"
			lets_encrypt_url 	= "production"
			timeout 			= "10m"
			description 		= "Updated Lets Encrypt target"
		}
	`, cfTargetName, cfTargetPath, targetName, targetPath, cfTargetName)

	resourceName := "akeyless_target_lets_encrypt." + targetName
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      testutils.CheckTargetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(targetPath),
					resource.TestCheckResourceAttr(resourceName, "dns_zone", "cf-zone-123"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(targetPath),
					resource.TestCheckResourceAttr(resourceName, "dns_zone", "cf-zone-456"),
				),
			},
		},
	})
}

func TestTargetDigiCertResource(t *testing.T) {
	eabKeyId := os.Getenv("AKEYLESS_DIGICERT_EAB_KEY_ID")
	eabHmacKey := os.Getenv("AKEYLESS_DIGICERT_EAB_HMAC_KEY")
	if eabKeyId == "" || eabHmacKey == "" {
		t.Skip("skipping: AKEYLESS_DIGICERT_EAB_KEY_ID and AKEYLESS_DIGICERT_EAB_HMAC_KEY must be set for DigiCert target tests")
	}

	dnsTargetName := "dns_target_digicert"
	dnsTargetPath := testPath(dnsTargetName)
	dnsTargetDetailsType := "aws_target_details"

	expect := map[string]any{
		"access_key_id": "test",
		"access_key":    "test",
		"region":        "us-east-1",
	}

	testutils.CreateTargetByType(t, dnsTargetPath, dnsTargetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, dnsTargetPath)
	})

	targetName := "digicert_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_digicert" "%v" {
			name             = "%v"
			email            = "test@example.com"
			acme_challenge   = "dns"
			digicert_url     = "us-demo"
			dns_target_creds = "%v"
			hosted_zone      = "Z1234567890"
			eab_hmac_key     = "%v"
			eab_key_id       = "%v"
			timeout          = "5m"
			description      = "Test DigiCert target"
		}
	`, targetName, targetPath, dnsTargetPath, eabHmacKey, eabKeyId)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_digicert" "%v" {
			name             = "%v"
			email            = "updated@example.com"
			digicert_url     = "eu-demo"
			dns_target_creds = "%v"
			hosted_zone      = "Z0987654321"
			eab_hmac_key     = "%v"
			eab_key_id       = "%v"
			timeout          = "10m"
			description      = "Updated DigiCert target"
		}
	`, targetName, targetPath, dnsTargetPath, eabHmacKey, eabKeyId)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetDigiCertResourceCloudflareDnsZone(t *testing.T) {
	eabKeyId := os.Getenv("AKEYLESS_DIGICERT_EAB_KEY_ID")
	eabHmacKey := os.Getenv("AKEYLESS_DIGICERT_EAB_HMAC_KEY")
	if eabKeyId == "" || eabHmacKey == "" {
		t.Skip("skipping: AKEYLESS_DIGICERT_EAB_KEY_ID and AKEYLESS_DIGICERT_EAB_HMAC_KEY must be set for DigiCert target tests")
	}

	cfTargetName := "digicert_cf_dns_target"
	cfTargetPath := testPath(cfTargetName)
	targetName := "digicert_target_cf"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_cloudflare" "%v" {
			name        = "%v"
			account_id  = "test-account-id"
			api_token   = "test-api-token"
		}

		resource "akeyless_target_digicert" "%v" {
			name             = "%v"
			email            = "test@example.com"
			acme_challenge   = "dns"
			digicert_url     = "us-demo"
			dns_target_creds = akeyless_target_cloudflare.%v.name
			dns_zone         = "cf-zone-123"
			eab_hmac_key     = "%v"
			eab_key_id       = "%v"
			timeout          = "5m"
			description      = "Test DigiCert target"
		}
	`, cfTargetName, cfTargetPath, targetName, targetPath, cfTargetName, eabHmacKey, eabKeyId)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_cloudflare" "%v" {
			name        = "%v"
			account_id  = "test-account-id"
			api_token   = "test-api-token"
		}

		resource "akeyless_target_digicert" "%v" {
			name             = "%v"
			email            = "updated@example.com"
			digicert_url     = "eu-demo"
			dns_target_creds = akeyless_target_cloudflare.%v.name
			dns_zone         = "cf-zone-456"
			eab_hmac_key     = "%v"
			eab_key_id       = "%v"
			timeout          = "10m"
			description      = "Updated DigiCert target"
		}
	`, cfTargetName, cfTargetPath, targetName, targetPath, cfTargetName, eabHmacKey, eabKeyId)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      testutils.CheckTargetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(targetPath),
					resource.TestCheckResourceAttr(targetPath, "dns_zone", "cf-zone-123"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckTargetExistsRemotely(targetPath),
					resource.TestCheckResourceAttr(targetPath, "dns_zone", "cf-zone-456"),
				),
			},
		},
	})
}

func TestTargetLinkedResource(t *testing.T) {
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

	testutils.TestTargetResource(t, providerFactories, secretPath, config, configUpdate, configUpdate2, configUpdate3, configUpdate4, configUpdate5)

}

func TestTargetOpenaiResource(t *testing.T) {
	targetName := "openai_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name                = "%v"
			api_key             = "test-api-key-1"
			openai_url          = "https://api.openai.com"
			description         = "Test OpenAI target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_openai" "%v" {
			name                = "%v"
			api_key             = "test-api-key-2"
			openai_url          = "https://api.openai.com"
			description         = "Updated OpenAI target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetPingResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetRabbitmqResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetSalesforceResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetSectigoResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetSplunkResource(t *testing.T) {
	t.Skip("skipping: Splunk target is not supported yet by the API")

	targetName := "splunk_target"
	targetPath := testPath(targetName)

	config := fmt.Sprintf(`
		resource "akeyless_target_splunk" "%v" {
			name 				= "%v"
			url 				= "https://splunk.example.com:8089"
			username 			= "user1"
			password 			= "test-password"
			audience 			= "splunk-audience"
			use_tls 			= true
			description 		= "Test Splunk target"
		}
	`, targetName, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_splunk" "%v" {
			name 				= "%v"
			url 				= "https://splunk.example.com:8089"
			username 			= "user2"
			splunk_token 		= "test-token"
			token_owner 		= "user2"
			audience 			= "splunk-audience"
			description 		= "Updated Splunk target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}

func TestTargetSshResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, secretPath)
}

func TestTargetWebResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, secretPath)
}

func TestTargetWindowsResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, secretPath)
}

func TestTargetZeroSslResource(t *testing.T) {
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

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}
