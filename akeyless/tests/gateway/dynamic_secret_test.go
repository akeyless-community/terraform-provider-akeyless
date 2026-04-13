package gateway

import (
	"context"
	"fmt"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"
)

func TestDynamicSecretArtifactory(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-artifactory"
	targetPath := testPath(targetName)
	targetDetailsType := "artifactory_target_details"

	expect := map[string]any{
		"base_url":   "http://www.test.com",
		"admin_name": "admin1",
		"admin_pwd":  "1234",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_artifactory_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_artifactory" "%v" {
			name                       = "%v"
			target_name                = "%v"
			artifactory_token_scope    = "member-of-groups:readers"
			artifactory_token_audience = "jfrt@*"
			artifactory_admin_name     = "admin"
			artifactory_admin_pwd      = "DummyPass123"
			base_url                   = "https://artifactory.example.com"
			user_ttl                   = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_artifactory" "%v" {
			name                       = "%v"
			target_name                = "%v"
			artifactory_token_scope    = "member-of-groups:deployers"
			artifactory_token_audience = "jfrt@*"
			artifactory_admin_name     = "admin"
			artifactory_admin_pwd      = "DummyPass123"
			base_url                   = "https://artifactory.example.com"
			user_ttl                   = "60m"
			tags                       = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretAws(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-aws"
	targetPath := testPath(targetName)
	targetDetailsType := "aws_target_details"

	expect := map[string]any{
		"access_key_id": "test",
		"access_key":    "test",
		"region":        "us-east-1",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_aws_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_aws" "%v" {
			name                 = "%v"
			target_name          = "%v"
			aws_access_key_id    = "test"
			aws_access_secret_key = "test"
			region               = "us-east-1"
			user_ttl             = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_aws" "%v" {
			name                 = "%v"
			target_name          = "%v"
			aws_access_key_id    = "test"
			aws_access_secret_key = "test"
			region               = "eu-west-1"
			user_ttl             = "60m"
			tags                 = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretAzure(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-azure"
	targetPath := testPath(targetName)
	targetDetailsType := "azure_target_details"

	expect := map[string]any{
		"tenant_id":       "00000000-0000-0000-0000-000000000001",
		"client_id":       "00000000-0000-0000-0000-000000000002",
		"client_secret":   "dummy-client-secret",
		"subscription_id": "00000000-0000-0000-0000-000000000003",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_azure_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_azure" "%v" {
			name                = "%v"
			target_name         = "%v"
			azure_tenant_id     = "00000000-0000-0000-0000-000000000001"
			azure_client_id     = "00000000-0000-0000-0000-000000000002"
			azure_client_secret = "dummy-client-secret"
			app_obj_id          = "00000000-0000-0000-0000-000000000003"
			user_ttl            = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_azure" "%v" {
			name                = "%v"
			target_name         = "%v"
			azure_tenant_id     = "00000000-0000-0000-0000-000000000001"
			azure_client_id     = "00000000-0000-0000-0000-000000000002"
			azure_client_secret = "dummy-client-secret-2"
			app_obj_id          = "00000000-0000-0000-0000-000000000003"
			user_ttl            = "60m"
			tags                = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretCassandra(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-cassandra"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "cassandra",
		"host":      "cassandra-db.example.com",
		"port":      "9042",
		"db_name":   "testdb",
		"user_name": "admin",
		"pwd":       "DummyPass123",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_cassandra_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_cassandra" "%v" {
			name               = "%v"
			target_name        = "%v"
			cassandra_username = "%v"
			cassandra_password = "%v"
			cassandra_hosts    = "%v"
			cassandra_port     = "%v"
			user_ttl           = "30m"
		}
	`, dsName, dsPath, targetPath, testutils.DockerCassandraUser, testutils.DockerCassandraPassword, testutils.DockerCassandraHost, testutils.DockerCassandraPort)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_cassandra" "%v" {
			name               = "%v"
			target_name        = "%v"
			cassandra_username = "%v"
			cassandra_password = "%v"
			cassandra_hosts    = "%v"
			cassandra_port     = "%v"
			user_ttl           = "60m"
			tags               = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath, testutils.DockerCassandraUser, testutils.DockerCassandraPassword, testutils.DockerCassandraHost, testutils.DockerCassandraPort)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretCustom(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	// no target needed for custom dynamic secret

	dsName := "ds_custom_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_custom" "%v" {
			name             = "%v"
			create_sync_url  = "https://webhook.example.com/create"
			revoke_sync_url  = "https://webhook.example.com/revoke"
			user_ttl         = "30m"
		}
	`, dsName, dsPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_custom" "%v" {
			name             = "%v"
			create_sync_url  = "https://webhook.example.com/create"
			revoke_sync_url  = "https://webhook.example.com/revoke"
			user_ttl         = "60m"
			tags             = ["test1", "test2"]
		}
	`, dsName, dsPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretDockerhub(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-dockerhub"
	targetPath := testPath(targetName)
	targetDetailsType := "dockerhub_target_details"

	expect := map[string]any{
		"username": "user1",
		"password": "1234",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_dockerhub_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_dockerhub" "%v" {
			name               = "%v"
			target_name        = "%v"
			dockerhub_username = "dummyuser"
			dockerhub_password = "DummyPass123"
			user_ttl           = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_dockerhub" "%v" {
			name               = "%v"
			target_name        = "%v"
			dockerhub_username = "dummyuser"
			dockerhub_password = "DummyPass123"
			user_ttl           = "60m"
			tags               = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretEks(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-eks"
	targetPath := testPath(targetName)
	targetDetailsType := "eks_target_details"

	expect := map[string]any{
		"cluster_name":     "test",
		"cluster_endpoint": "https://www.test.com",
		"cluster_ca_cert":  "YmxhYmxh",
		"access_key_id":    "test",
		"access_key":       "test",
		"region":           "il-central-1",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_eks_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_eks" "%v" {
			name                  = "%v"
			target_name           = "%v"
			eks_access_key_id     = "test"
			eks_secret_access_key = "test"
			eks_region            = "us-east-1"
			eks_cluster_name      = "test-cluster"
			eks_cluster_endpoint  = "https://eks.example.com"
			eks_cluster_ca_cert   = "LS0tLS1CRUdJTi..."
			user_ttl              = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_eks" "%v" {
			name                  = "%v"
			target_name           = "%v"
			eks_access_key_id     = "test"
			eks_secret_access_key = "test"
			eks_region            = "eu-west-1"
			eks_cluster_name      = "test-cluster"
			eks_cluster_endpoint  = "https://eks.example.com"
			eks_cluster_ca_cert   = "LS0tLS1CRUdJTi..."
			user_ttl              = "60m"
			tags                  = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretGcp(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-gcp"
	targetPath := testPath(targetName)
	targetDetailsType := "gcp_target_details"

	expect := map[string]any{
		"gcp_service_account_key": testutils.GCP_KEY,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_gcp_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gcp" "%v" {
			name              = "%v"
			target_name       = "%v"
			gcp_sa_email      = "test@test.com"
			gcp_key           = "eyJkdW1teSI6ICJ0ZXN0In0="
			service_account_type = "fixed"
			gcp_token_scopes  = "https://www.googleapis.com/auth/cloud-platform"
			user_ttl          = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gcp" "%v" {
			name              = "%v"
			target_name       = "%v"
			gcp_sa_email      = "test@test.com"
			gcp_key           = "eyJkdW1teSI6ICJ0ZXN0In0="
			service_account_type = "fixed"
			gcp_token_scopes  = "https://www.googleapis.com/auth/cloud-platform"
			user_ttl          = "60m"
			tags              = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretGoogleWorkspace(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-gws"
	targetPath := testPath(targetName)
	targetDetailsType := "gcp_target_details"

	expect := map[string]any{
		"gcp_service_account_key": testutils.GCP_KEY,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_google_workspace_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_google_workspace" "%v" {
			name        = "%v"
			target_name = "%v"
			access_mode = "role"
			admin_email = "admin@example.com"
			role_name   = "_SEED_ADMIN_ROLE"
			role_scope  = "ORG_UNIT"
			gcp_key     = "eyJkdW1teSI6ICJ0ZXN0In0="
			user_ttl    = "30m"
			tags        = ["t1", "t2"]
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_google_workspace" "%v" {
			name        = "%v"
			target_name = "%v"
			access_mode = "group"
			admin_email = "admin@example.com"
			group_email = "group@example.com"
			group_role  = "MEMBER"
			gcp_key     = "eyJkdW1teSI6ICJ0ZXN0In0="
			user_ttl    = "60m"
			tags        = ["t1", "t3"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretGithubResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	const (
		GITHUB_TOKEN_PERM = `["contents=read", "issues=write", "actions=read"]`
		GITHUB_TOKEN_REPO = `["github-producer-test1", "github-producer-test2"]`
	)

	targetName := "test-target-github"
	targetPath := testPath(targetName)
	targetDetailsType := "github_target_details"

	expect := map[string]any{
		"app_id":          1234,
		"app_private_key": "test",
		"base_url":        "http://127.0.0.1:81",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "github_test"
	dsPath := testPath(dsName)
	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name                      = "%v"
			target_name               = "%v"
			installation_id           = 1234
			installation_organization = "test"
			token_permissions         = %v
			github_app_id             = 1234
			github_app_private_key    = "test"
			token_ttl                 = "50m"
		}
	`, dsName, dsPath, targetPath, GITHUB_TOKEN_PERM)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name                      = "%v"
			target_name               = "%v"
			installation_id           = "1234"
			installation_repository   = "test"
			installation_organization = "test"
			token_repositories        = %v
			github_app_id             = 1234
			github_app_private_key    = "test"
			token_ttl                 = "40m"
		}
	`, dsName, dsPath, targetPath, GITHUB_TOKEN_REPO)

	configUpdate2 := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_github" "%v" {
			name                    = "%v"
			target_name             = "%v"
			installation_repository = "test"
			token_repositories      = %v
			github_app_id           = 1234
			github_app_private_key  = "test"
			token_ttl               = "40m"
		}
	`, dsName, dsPath, targetPath, GITHUB_TOKEN_REPO)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate, configUpdate2)
}

func TestDynamicSecretGitlabResource(t *testing.T) {

	testutils.SkipIfNoGateway(t)

	targetName := "test-target-gitlab"
	targetPath := testPath(targetName)
	targetDetailsType := "gitlab_target_details"

	expect := map[string]any{
		"access_token": "test",
		"url":          "http://127.0.0.1:81",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "gitlab_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gitlab" "%v" {
			name            	= "%v"
			target_name         = "%v"
  			gitlab_url          = "http://127.0.0.1:81"
  			gitlab_token_scopes = "api"
  			gitlab_access_type  = "group"
  			group_name          = "mygroup"
  			ttl      			= "10m"
  			gitlab_access_token = "test"
			tags                = ["t1", "t2"]
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gitlab" "%v" {
			name            	= "%v"
			target_name         = "%v"
  			gitlab_url          = "http://127.0.0.1:81"
  			gitlab_token_scopes = "api"
  			gitlab_access_type  = "group"
  			group_name          = "mygroup2"
  			gitlab_access_token = "test"
			tags                = ["t1", "t2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretGke(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-gke"
	targetPath := testPath(targetName)
	targetDetailsType := "gke_target_details"

	expect := map[string]any{
		"service_account_email": "test@test.com",
		"cluster_endpoint":      "https://www.test.com",
		"cluster_ca_cert":       "YmxhYmxh",
		"service_account_key":   "test",
		"cluster_name":          "test",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_gke_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gke" "%v" {
			name                      = "%v"
			target_name               = "%v"
			gke_account_key           = "eyJkdW1teSI6ICJ0ZXN0In0="
			gke_cluster_endpoint      = "https://gke.example.com"
			gke_cluster_cert          = "LS0tLS1CRUdJTi..."
			gke_service_account_email = "test@test.com"
			gke_cluster_name          = "test-cluster"
			user_ttl                  = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_gke" "%v" {
			name                      = "%v"
			target_name               = "%v"
			gke_account_key           = "eyJkdW1teSI6ICJ0ZXN0In0="
			gke_cluster_endpoint      = "https://gke.example.com"
			gke_cluster_cert          = "LS0tLS1CRUdJTi..."
			gke_service_account_email = "test@test.com"
			gke_cluster_name          = "test-cluster"
			user_ttl                  = "60m"
			tags                      = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretHanaDb(t *testing.T) {
	t.Skip("TODO: SDK is broken. Need to send to hanadb, not to hana.")
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-hana"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "hanadb",
		"host":      "hana-db.example.com",
		"port":      "30015",
		"user_name": "SYSTEM",
		"pwd":       "DummyPass123",
		"db_name":   "SYSTEMDB",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_hana_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_hana_db" "%v" {
			name             = "%v"
			target_name      = "%v"
			hanadb_username  = "SYSTEM"
			hanadb_password  = "DummyPass123"
			hanadb_host      = "hana-db.example.com"
			hanadb_port      = "30015"
			hana_dbname      = "testdb"
			user_ttl         = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_hana_db" "%v" {
			name             = "%v"
			target_name      = "%v"
			hanadb_username  = "SYSTEM"
			hanadb_password  = "DummyPass123"
			hanadb_host      = "hana-db.example.com"
			hanadb_port      = "30015"
			hana_dbname      = "testdb"
			user_ttl         = "60m"
			tags             = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretK8s(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	cert := testutils.GenerateCert(t)

	targetName := "test-target-k8s"
	targetPath := testPath(targetName)
	targetDetailsType := "native_k8s_target_details"

	expect := map[string]any{
		"cluster_endpoint": "https://www.test.com",
		"cluster_ca_cert":  "YmxhYmxh",
		"bearer_token":     "Ymxh",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_k8s_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_k8s" "%v" {
			name                   = "%v"
			target_name            = "%v"
			k8s_cluster_endpoint   = "https://k8s-api.example.com:6443"
			k8s_cluster_ca_cert    = "%v"
			k8s_cluster_token      = "eyJhbGciOiJSUzI1NiIsImR1bW15IjoidGVzdCJ9"
			k8s_namespace          = "default"
			k8s_service_account    = "test-sa"
			user_ttl               = "30m"
		}
	`, dsName, dsPath, targetPath, cert)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_k8s" "%v" {
			name                   = "%v"
			target_name            = "%v"
			k8s_cluster_endpoint   = "https://k8s-api.example.com:6443"
			k8s_cluster_ca_cert    = "%v"
			k8s_cluster_token      = "eyJhbGciOiJSUzI1NiIsImR1bW15IjoidGVzdCJ9"
			k8s_namespace          = "production"
			k8s_service_account    = "test-sa"
			user_ttl               = "60m"
			tags                   = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath, cert)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretLdap(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-ldap"
	targetPath := testPath(targetName)
	targetDetailsType := "ldap_target_details"

	expect := map[string]any{
		"url":           "ldap://ldap.example.com:389",
		"bind_dn":       "cn=admin,dc=example,dc=com",
		"bind_password": "DummyPass123",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_ldap_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_ldap" "%v" {
			name             = "%v"
			target_name      = "%v"
			ldap_url         = "ldap://ldap.example.com:389"
			bind_dn          = "cn=admin,dc=example,dc=com"
			bind_dn_password = "DummyPass123"
			user_dn          = "ou=users,dc=example,dc=com"
			user_ttl         = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_ldap" "%v" {
			name             = "%v"
			target_name      = "%v"
			ldap_url         = "ldap://ldap.example.com:389"
			bind_dn          = "cn=admin,dc=example,dc=com"
			bind_dn_password = "DummyPass123"
			user_dn          = "ou=users,dc=example,dc=com"
			user_ttl         = "60m"
			tags             = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretMongo(t *testing.T) {
	t.Skip("TODO: SDK is broken. Need to send to mongodb, not to mongo.")
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-mongo"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "mongodb",
		"host":      "mongodb-db.example.com",
		"port":      "27017",
		"db_name":   "testdb",
		"user_name": "admin",
		"pwd":       "DummyPass123",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_mongo_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mongodb" "%v" {
			name                   = "%v"
			target_name            = "%v"
			mongodb_username       = "%v"
			mongodb_password       = "%v"
			mongodb_host_port      = "%v:%v"
			mongodb_default_auth_db = "admin"
			mongodb_name           = "%v"
			user_ttl               = "30m"
		}
	`, dsName, dsPath, targetPath, testutils.DockerMongoUser, testutils.DockerMongoPassword, testutils.DockerMongoHost, testutils.DockerMongoPort, testutils.DockerMongoDB)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mongodb" "%v" {
			name                   = "%v"
			target_name            = "%v"
			mongodb_username       = "%v"
			mongodb_password       = "%v"
			mongodb_host_port      = "%v:%v"
			mongodb_default_auth_db = "admin"
			mongodb_name           = "%v"
			user_ttl               = "60m"
			tags                   = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath, testutils.DockerMongoUser, testutils.DockerMongoPassword, testutils.DockerMongoHost, testutils.DockerMongoPort, testutils.DockerMongoDB)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretMssql(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-db"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "mssql",
		"user_name": "test",
		"pwd":       "test",
		"host":      "127.0.0.1",
		"port":      "1433",
		"db_name":   "test",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_mssql_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mssql" "%v" {
			name           = "%v"
			target_name    = "%v"
			mssql_username = "%v"
			mssql_password = "%v"
			mssql_host     = "%v"
			mssql_port     = "%v"
			mssql_dbname   = "%v"
			user_ttl       = "30m"
		}
	`, dsName, dsPath, targetPath, testutils.DockerMssqlUser, testutils.DockerMssqlPassword, testutils.DockerMssqlHost, testutils.DockerMssqlPort, testutils.DockerMssqlDB)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mssql" "%v" {
			name           = "%v"
			target_name    = "%v"
			mssql_username = "%v"
			mssql_password = "%v"
			mssql_host     = "%v"
			mssql_port     = "%v"
			mssql_dbname   = "%v"
			user_ttl       = "60m"
			tags           = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath, testutils.DockerMssqlUser, testutils.DockerMssqlPassword, testutils.DockerMssqlHost, testutils.DockerMssqlPort, testutils.DockerMssqlDB)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretMysql(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-db"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "mysql",
		"user_name": "test",
		"pwd":       "test",
		"host":      "127.0.0.1",
		"port":      "3306",
		"db_name":   "test",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_mysql_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mysql" "%v" {
			name           = "%v"
			target_name    = "%v"
			mysql_username = "%v"
			mysql_password = "%v"
			mysql_host     = "%v"
			mysql_port     = "%v"
			mysql_dbname   = "%v"
			user_ttl       = "30m"
		}
	`, dsName, dsPath, targetPath, testutils.DockerMysqlUser, testutils.DockerMysqlPassword, testutils.DockerMysqlHost, testutils.DockerMysqlPort, testutils.DockerMysqlDB)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mysql" "%v" {
			name           = "%v"
			target_name    = "%v"
			mysql_username = "%v"
			mysql_password = "%v"
			mysql_host     = "%v"
			mysql_port     = "%v"
			mysql_dbname   = "%v"
			user_ttl       = "60m"
			tags           = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath, testutils.DockerMysqlUser, testutils.DockerMysqlPassword, testutils.DockerMysqlHost, testutils.DockerMysqlPort, testutils.DockerMysqlDB)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretOpenai(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-openai"
	targetPath := testPath(targetName)
	targetDetailsType := "openai_target_details"

	expect := map[string]any{
		"openai_url":      "https://api.openai.com",
		"api_key":         "test",
		"organization_id": "test",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_openai_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_openai" "%v" {
			name        = "%v"
			target_name = "%v"
			project_id  = "proj-dummy-123"
			user_ttl    = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_openai" "%v" {
			name        = "%v"
			target_name = "%v"
			project_id  = "proj-dummy-123"
			user_ttl    = "60m"
			tags        = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretOracle(t *testing.T) {
	t.Skip("TODO: SDK is broken. Need to send to oracledb, not to oracle.")
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-oracle"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":      "oracle",
		"host":         "oracle-db.example.com",
		"port":         "1521",
		"user_name":    "admin",
		"pwd":          "DummyPass123",
		"service_name": "ORCL",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_oracle_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_oracle" "%v" {
			name            = "%v"
			target_name     = "%v"
			oracle_username = "admin"
			oracle_password = "DummyPass123"
			oracle_host     = "oracle-db.example.com"
			oracle_port     = "1521"
			oracle_service_name = "ORCL"
			user_ttl        = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_oracle" "%v" {
			name            = "%v"
			target_name     = "%v"
			oracle_username = "admin"
			oracle_password = "DummyPass123"
			oracle_host     = "oracle-db.example.com"
			oracle_port     = "1521"
			oracle_service_name = "ORCL"
			user_ttl        = "60m"
			tags            = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretPing(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-ping"
	targetPath := testPath(targetName)
	targetDetailsType := "ping_target_details"

	expect := map[string]any{
		"url":                 "https://console.akeyless.io",
		"privileged_user":     "Administrator",
		"user_password":       "1234",
		"administrative_port": "9999",
		"authorization_port":  "9031",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_ping_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_ping" "%v" {
			name                 = "%v"
			target_name          = "%v"
			ping_url             = "https://example.com"
			ping_privileged_user = "admin"
			ping_password        = "DummyPass123"
			ping_redirect_uris   = ["https://example.com/callback"]
			user_ttl             = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_ping" "%v" {
			name                 = "%v"
			target_name          = "%v"
			ping_url             = "https://example.com"
			ping_privileged_user = "admin"
			ping_password        = "DummyPass123"
			ping_redirect_uris   = ["https://example.com/callback"]
			user_ttl             = "60m"
			tags                 = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretPostgresql(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-db"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "postgres",
		"host":      "postgresql-db.example.com",
		"port":      "5432",
		"user_name": "admin",
		"pwd":       "DummyPass123",
		"db_name":   "testdb",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_postgres_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_postgresql" "%v" {
			name                = "%v"
			target_name         = "%v"
			postgresql_username = "%v"
			postgresql_password = "%v"
			postgresql_host     = "%v"
			postgresql_port     = "%v"
			postgresql_db_name  = "%v"
			user_ttl            = "30m"
		}
	`, dsName, dsPath, targetPath, testutils.DockerPostgresUser, testutils.DockerPostgresPassword, testutils.DockerPostgresHost, testutils.DockerPostgresPort, testutils.DockerPostgresDB)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_postgresql" "%v" {
			name                = "%v"
			target_name         = "%v"
			postgresql_username = "%v"
			postgresql_password = "%v"
			postgresql_host     = "%v"
			postgresql_port     = "%v"
			postgresql_db_name  = "%v"
			user_ttl            = "60m"
			tags                = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath, testutils.DockerPostgresUser, testutils.DockerPostgresPassword, testutils.DockerPostgresHost, testutils.DockerPostgresPort, testutils.DockerPostgresDB)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretRabbitmq(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-rabbitmq"
	targetPath := testPath(targetName)
	targetDetailsType := "rabbit_mq_target_details"

	expect := map[string]any{
		"rabbitmq_type":   "rabbitmq",
		"server_user":     "test",
		"server_password": "test",
		"server_uri":      "http://127.0.0.1:15672",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_rabbitmq_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_rabbitmq" "%v" {
			name                           = "%v"
			target_name                    = "%v"
			rabbitmq_admin_user            = "%v"
			rabbitmq_admin_pwd             = "%v"
			rabbitmq_server_uri            = "%v"
			rabbitmq_user_tags             = "management"
			rabbitmq_user_conf_permission  = ".*"
			rabbitmq_user_read_permission  = ".*"
			rabbitmq_user_write_permission = ".*"
			user_ttl                       = "30m"
		}
	`, dsName, dsPath, targetPath, testutils.DockerRabbitmqUser, testutils.DockerRabbitmqPassword, testutils.DockerRabbitmqURI)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_rabbitmq" "%v" {
			name                           = "%v"
			target_name                    = "%v"
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
	`, dsName, dsPath, targetPath, testutils.DockerRabbitmqUser, testutils.DockerRabbitmqPassword, testutils.DockerRabbitmqURI)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretRdp(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-rdp"
	targetPath := testPath(targetName)
	targetDetailsType := "windows_target_details"

	expect := map[string]any{
		"hostname": "windows.example.com",
		"username": "administrator",
		"password": "DummyPass123",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_rdp_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_rdp" "%v" {
			name            = "%v"
			target_name     = "%v"
			rdp_admin_name  = "administrator"
			rdp_admin_pwd   = "DummyPass123"
			rdp_host_name   = "rdp.example.com"
			rdp_host_port   = "3389"
			rdp_user_groups = "Administrators"
			user_ttl        = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_rdp" "%v" {
			name            = "%v"
			target_name     = "%v"
			rdp_admin_name  = "administrator"
			rdp_admin_pwd   = "DummyPass123"
			rdp_host_name   = "rdp.example.com"
			rdp_host_port   = "3389"
			rdp_user_groups = "Administrators"
			user_ttl        = "60m"
			tags            = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretRedis(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-redis"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "redis",
		"user_name": "test",
		"pwd":       "test",
		"host":      "127.0.0.1",
		"port":      "6379",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_redis_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_redis" "%v" {
			name     = "%v"
			target_name = "%v"
			username = "%v"
			password = "%v"
			host     = "%v"
			port     = "%v"
			user_ttl = "30m"
		}
	`, dsName, dsPath, targetPath, testutils.DockerRedisUser, testutils.DockerRedisPassword, testutils.DockerRedisHost, testutils.DockerRedisPort)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_redis" "%v" {
			name     = "%v"
			target_name = "%v"
			username = "%v"
			password = "%v"
			host     = "%v"
			port     = "%v"
			user_ttl = "60m"
			tags     = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath, testutils.DockerRedisUser, testutils.DockerRedisPassword, testutils.DockerRedisHost, testutils.DockerRedisPort)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretRedshift(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-redshift"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "redshift",
		"host":      "redshift-cluster.example.com",
		"port":      "5439",
		"user_name": "admin",
		"pwd":       "DummyPass123",
		"db_name":   "dev",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_redshift_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_redshift" "%v" {
			name              = "%v"
			target_name       = "%v"
			redshift_username = "admin"
			redshift_password = "DummyPass123"
			redshift_host     = "redshift-cluster.example.com"
			redshift_port     = "5439"
			redshift_db_name  = "testdb"
			user_ttl          = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_redshift" "%v" {
			name              = "%v"
			target_name       = "%v"
			redshift_username = "admin"
			redshift_password = "DummyPass123"
			redshift_host     = "redshift-cluster.example.com"
			redshift_port     = "5439"
			redshift_db_name  = "testdb"
			user_ttl          = "60m"
			tags              = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretSnowflake(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-snowflake"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":           "snowflake",
		"host":              "test-account.snowflakecomputing.com",
		"port":              "443",
		"user_name":         "admin",
		"pwd":               "DummyPass123",
		"db_name":           "TESTDB",
		"snowflake_account": "test-account",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_snowflake_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_snowflake" "%v" {
			name             = "%v"
			target_name      = "%v"
			account_username = "admin"
			account_password = "DummyPass123"
			account          = "test-account.snowflakecomputing.com"
			db_name          = "TESTDB"
			user_ttl         = "30m"
		}
	`, dsName, dsPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_snowflake" "%v" {
			name             = "%v"
			target_name      = "%v"
			account_username = "admin"
			account_password = "DummyPass123"
			account          = "test-account.snowflakecomputing.com"
			db_name          = "TESTDB"
			user_ttl         = "60m"
			tags             = ["test1", "test2"]
		}
	`, dsName, dsPath, targetPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretVenafi(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	// no target needed for venafi dynamic secret

	dsName := "ds_venafi_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_venafi" "%v" {
			name            = "%v"
			venafi_api_key  = "dummy-api-key-12345"
			venafi_zone     = "Test\\Policy"
			venafi_baseurl  = "https://venafi.example.com"
			user_ttl        = "30m"
		}
	`, dsName, dsPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_venafi" "%v" {
			name            = "%v"
			venafi_api_key  = "dummy-api-key-12345"
			venafi_zone     = "Test\\Policy"
			venafi_baseurl  = "https://venafi.example.com"
			user_ttl        = "60m"
			tags            = ["test1", "test2"]
		}
	`, dsName, dsPath)

	testutils.TestItemResource(t, providerFactories, dsPath, config, configUpdate)
}

func TestDynamicSecretDataSource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "test-target-db"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]any{
		"db_type":   "mysql",
		"user_name": testutils.DockerMysqlUser,
		"pwd":       testutils.DockerMysqlPassword,
		"host":      testutils.DockerMysqlHost,
		"port":      testutils.DockerMysqlPort,
		"db_name":   testutils.DockerMysqlDB,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	dsName := "ds_mysql_test"
	dsPath := testPath(dsName)

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_mysql" "%v" {
			name            = "%v"
			target_name     = "%v"
			user_ttl        = "5m"
		}
		data "akeyless_dynamic_secret" "ds" {
			path       = "%v"
			depends_on = [akeyless_dynamic_secret_mysql.%v]
		}
	`, dsName, dsPath, targetPath, dsPath, dsName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.akeyless_dynamic_secret.ds", "value"),
				),
			},
		},
	})
}

func TestDynamicSecretTmpCreds(t *testing.T) {

	t.Skip("TODO: SDK is broken, skipping")

	testutils.SkipIfNoGateway(t)

	client, token := testutils.PrepareClient(t)
	ctx := context.Background()

	// Create a MySQL target via API
	targetName := "test-target-tmp-creds"
	targetPath := testPath(targetName)
	testutils.CreateTargetByType(t, targetPath, "db_target_details", map[string]any{
		"db_type":   "mysql",
		"user_name": testutils.DockerMysqlUser,
		"pwd":       testutils.DockerMysqlPassword,
		"host":      testutils.DockerMysqlHost,
		"port":      testutils.DockerMysqlPort,
		"db_name":   testutils.DockerMysqlDB,
	})
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	// Create a MySQL dynamic secret via API
	dsPath := testPath("ds_tmp_creds_test")
	createBody := akeyless_api.DynamicSecretCreateMySql{
		Name:       dsPath,
		Token:      &token,
		TargetName: akeyless_api.PtrString(targetPath),
	}
	_, _, err := client.DynamicSecretCreateMySql(ctx).Body(createBody).Execute()
	require.NoError(t, err)
	t.Cleanup(func() {
		testutils.DeleteItem(t, dsPath)
	})

	// Get value to produce a temporary user
	getValBody := akeyless_api.DynamicSecretGetValue{
		Name:  dsPath,
		Token: &token,
	}
	_, _, err = client.DynamicSecretGetValue(ctx).Body(getValBody).Execute()
	require.NoError(t, err)

	// Fetch tmp creds list and extract the ID
	getTmpBody := akeyless_api.DynamicSecretTmpCredsGet{
		Name:  dsPath,
		Token: &token,
	}
	tmpCreds, _, err := client.DynamicSecretTmpCredsGet(ctx).Body(getTmpBody).Execute()
	require.NoError(t, err)
	require.Len(t, tmpCreds, 1, "expected exactly one tmp creds entry after get-value")
	require.NotNil(t, tmpCreds[0].Id)

	tmpCredsId := *tmpCreds[0].Id

	resourceName := "akeyless_dynamic_secret_tmp_creds.test"

	config := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_tmp_creds" "test" {
			name         = "%v"
			tmp_creds_id = "%v"
			new_ttl_min  = 30
		}
	`, dsPath, tmpCredsId)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dynamic_secret_tmp_creds" "test" {
			name         = "%v"
			tmp_creds_id = "%v"
			new_ttl_min  = 60
		}
	`, dsPath, tmpCredsId)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy: func(s *terraform.State) error {
			getTmp := akeyless_api.DynamicSecretTmpCredsGet{
				Name:  dsPath,
				Token: &token,
			}
			creds, _, err := client.DynamicSecretTmpCredsGet(ctx).Body(getTmp).Execute()
			if err != nil {
				return nil
			}
			for _, c := range creds {
				if c.Id != nil && *c.Id == tmpCredsId {
					return fmt.Errorf("tmp creds %s still exists", tmpCredsId)
				}
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tmp_creds_id", tmpCredsId),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tmp_creds_id", tmpCredsId),
				),
			},
		},
	})
}
