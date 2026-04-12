package testutils

import (
	"context"
	"strings"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/stretchr/testify/require"
)

type CreateTargetFunc func(t *testing.T, name string, details map[string]any)

var CreateTargetByTypeMap = map[string]CreateTargetFunc{
	"artifactory_target_details":      CreateArtifactoryTarget,
	"aws_target_details":              CreateAwsTarget,
	"azure_target_details":            CreateAzureTarget,
	"db_target_details":               CreateDbTarget,
	"dockerhub_target_details":        CreateDockerHubTarget,
	"eks_target_details":              CreateEksTarget,
	"gcp_target_details":              CreateGcpTarget,
	"github_target_details":           CreateGithubTarget,
	"gitlab_target_details":           CreateGitlabTarget,
	"gke_target_details":              CreateGkeTarget,
	"globalsign_atlas_target_details": CreateGlobalSignAtlasTarget,
	"globalsign_target_details":       CreateGlobalSignTarget,
	"hashi_target_details":            CreateHashiTarget,
	"ldap_target_details":             CreateLdapTarget,
	"linked_target_details":           CreateLinkedTarget,
	"mongo_db_target_details":         CreateMongoDbTarget,
	"native_k8s_target_details":       CreateK8sTarget,
	"ping_target_details":             CreatePingTarget,
	"rabbit_mq_target_details":        CreateRabbitMqTarget,
	"salesforce_target_details":       CreateSalesforceTarget,
	"ssh_target_details":              CreateSshTarget,
	"venafi_target_details":           nil,
	"web_target_details":              CreateWebTarget,
	"windows_target_details":          CreateWindowsTarget,
	"zerossl_target_details":          CreateZeroSslTarget,
}

func CreateTargetByType(t *testing.T, name, targetType string, details map[string]any) {
	CreateTargetByTypeMap[targetType](t, name, details)
}

func CreateArtifactoryTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateArtifactoryTarget{
		Name:                 name,
		Token:                &token,
		ArtifactoryAdminName: details["admin_name"].(string),
		ArtifactoryAdminPwd:  details["admin_pwd"].(string),
		BaseUrl:              details["base_url"].(string),
	}

	_, resp, err := client.CreateArtifactoryTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create artifactory target for test", resp, err))
}

func CreateAwsTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateAWSTarget{
		Name:        name,
		Token:       &token,
		AccessKeyId: details["access_key_id"].(string),
		AccessKey:   details["access_key"].(string),
	}
	common.GetAkeylessPtr(&body.Token, details["session_token"])
	common.GetAkeylessPtr(&body.Region, details["region"])
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, details["use_gw_cloud_identity"])

	_, resp, err := client.CreateAWSTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create aws target for test", resp, err))
}

func CreateAzureTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateAzureTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ClientId, details["client_id"])
	common.GetAkeylessPtr(&body.TenantId, details["tenant_id"])
	common.GetAkeylessPtr(&body.ClientSecret, details["client_secret"])
	common.GetAkeylessPtr(&body.SubscriptionId, details["subscription_id"])
	common.GetAkeylessPtr(&body.ResourceGroupName, details["resource_group_name"])
	common.GetAkeylessPtr(&body.ResourceName, details["resource_name"])
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, details["use_gw_cloud_identity"])

	_, resp, err := client.CreateAzureTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create azure target for test", resp, err))
}

func CreateDbTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.TargetCreateDB{
		Name:   name,
		Token:  &token,
		DbType: details["db_type"].(string),
	}
	common.GetAkeylessPtr(&body.UserName, details["user_name"])
	common.GetAkeylessPtr(&body.Pwd, details["pwd"])
	common.GetAkeylessPtr(&body.Host, details["host"])
	common.GetAkeylessPtr(&body.Port, details["port"])
	common.GetAkeylessPtr(&body.DbName, details["db_name"])
	common.GetAkeylessPtr(&body.Ssl, details["ssl_connection_mode"])
	common.GetAkeylessPtr(&body.SslCertificate, details["ssl_connection_certificate"])
	common.GetAkeylessPtr(&body.OracleServiceName, details["service_name"])
	common.GetAkeylessPtr(&body.DbServerName, details["server_name"])
	common.GetAkeylessPtr(&body.OracleWalletLoginType, details["wallet_login_type"])
	common.GetAkeylessPtr(&body.OracleWalletP12FileData, details["wallet_p12_file_data"])
	common.GetAkeylessPtr(&body.OracleWalletSsoFileData, details["wallet_sso_file_data"])
	common.GetAkeylessPtr(&body.SnowflakeAccount, details["snowflake_account"])

	_, resp, err := client.TargetCreateDB(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create db target for test", resp, err))
}

func CreateDockerHubTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateDockerhubTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DockerhubUsername, details["username"])
	common.GetAkeylessPtr(&body.DockerhubPassword, details["password"])

	_, resp, err := client.CreateDockerhubTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create dockerhub target for test", resp, err))
}

func CreateEksTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateEKSTarget{
		Name:               name,
		Token:              &token,
		EksClusterName:     details["cluster_name"].(string),
		EksClusterEndpoint: details["cluster_endpoint"].(string),
		EksClusterCaCert:   details["cluster_ca_cert"].(string),
		EksAccessKeyId:     details["access_key_id"].(string),
		EksSecretAccessKey: details["access_key"].(string),
	}
	common.GetAkeylessPtr(&body.EksRegion, details["region"])

	_, resp, err := client.CreateEKSTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create eks target for test", resp, err))
}

func CreateGcpTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.TargetCreateGcp{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GcpKey, details["gcp_service_account_key"])

	_, resp, err := client.TargetCreateGcp(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create gcp target for test", resp, err))
}

func CreateGithubTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.TargetCreateGithub{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GithubAppId, details["app_id"])
	common.GetAkeylessPtr(&body.GithubAppPrivateKey, details["app_private_key"])
	common.GetAkeylessPtr(&body.GithubBaseUrl, details["base_url"])

	_, resp, err := client.TargetCreateGithub(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create github target for test", resp, err))
}

func CreateGitlabTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.TargetCreateGitlab{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GitlabAccessToken, details["access_token"])
	common.GetAkeylessPtr(&body.GitlabUrl, details["url"])

	_, resp, err := client.TargetCreateGitlab(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create gitlab target for test", resp, err))
}

func CreateGkeTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateGKETarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GkeServiceAccountEmail, details["service_account_email"])
	common.GetAkeylessPtr(&body.GkeClusterEndpoint, details["cluster_endpoint"])
	common.GetAkeylessPtr(&body.GkeClusterCert, details["cluster_ca_cert"])
	common.GetAkeylessPtr(&body.GkeAccountKey, details["service_account_key"])
	common.GetAkeylessPtr(&body.GkeClusterName, details["cluster_name"])

	_, resp, err := client.CreateGKETarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create gke target for test", resp, err))
}

func CreateGlobalSignAtlasTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateGlobalSignAtlasTarget{
		Name:      name,
		Token:     &token,
		ApiKey:    details["api_key"].(string),
		ApiSecret: details["api_secret"].(string),
	}
	common.GetAkeylessPtr(&body.MtlsCertDataBase64, details["mutual_tls_cert"])
	common.GetAkeylessPtr(&body.MtlsKeyDataBase64, details["mutual_tls_key"])
	common.GetAkeylessPtr(&body.Timeout, details["timeout"])

	_, resp, err := client.CreateGlobalSignAtlasTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create globalsign atlas target for test", resp, err))
}

func CreateGlobalSignTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateGlobalSignTarget{
		Name:             name,
		Token:            &token,
		Username:         details["username"].(string),
		Password:         details["password"].(string),
		ProfileId:        details["profile_id"].(string),
		ContactFirstName: details["contact_first_name"].(string),
		ContactLastName:  details["contact_last_name"].(string),
		ContactPhone:     details["contact_phone"].(string),
		ContactEmail:     details["contact_email"].(string),
	}
	common.GetAkeylessPtr(&body.Timeout, details["timeout"])

	_, resp, err := client.CreateGlobalSignTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create globalsign target for test", resp, err))
}

func CreateHashiTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateHashiVaultTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.HashiUrl, details["vault_url"])
	common.GetAkeylessPtr(&body.VaultToken, details["vault_token"])
	common.GetAkeylessPtr(&body.Namespace, details["vault_namespaces"])

	_, resp, err := client.CreateHashiVaultTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create hashi vault target for test", resp, err))
}

func CreateLdapTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateLdapTarget{
		Name:           name,
		Token:          &token,
		LdapUrl:        details["url"].(string),
		BindDn:         details["bind_dn"].(string),
		BindDnPassword: details["bind_password"].(string),
	}
	common.GetAkeylessPtr(&body.TokenExpiration, details["token_expiration_in_sec"])
	common.GetAkeylessPtr(&body.LdapCaCert, details["certificate"])
	common.GetAkeylessPtr(&body.ServerType, details["implementation_type"])

	_, resp, err := client.CreateldapTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create ldap target for test", resp, err))
}

func CreateLinkedTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateLinkedTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Hosts, details["hosts"])
	common.GetAkeylessPtr(&body.ParentTargetName, details["parent"])

	_, resp, err := client.CreateLinkedTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create linked target for test", resp, err))
}

func CreateK8sTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateNativeK8STarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.K8sClusterEndpoint, details["cluster_endpoint"].(string))
	common.GetAkeylessPtr(&body.K8sClusterCaCert, details["cluster_ca_cert"].(string))
	common.GetAkeylessPtr(&body.K8sClusterToken, details["bearer_token"].(string))

	_, resp, err := client.CreateNativeK8STarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create k8s target for test", resp, err))
}

func CreateMongoDbTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	hostAndPort := strings.Split(details["host_port"].(string), ":")
	host := hostAndPort[0]
	port := hostAndPort[1]

	body := akeyless_api.CreateDBTarget{
		Name:   name,
		Token:  &token,
		DbType: "mongodb",
	}
	common.GetAkeylessPtr(&body.UserName, details["username"])
	common.GetAkeylessPtr(&body.Pwd, details["password"])
	common.GetAkeylessPtr(&body.DbName, details["db_name"])
	common.GetAkeylessPtr(&body.MongodbUriOptions, details["uri_options"])
	common.GetAkeylessPtr(&body.MongodbDefaultAuthDb, details["default_auth_db"])
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.Port, port)

	_, resp, err := client.CreateDBTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create mongodb target for test", resp, err))
}

func CreatePingTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreatePingTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.PingUrl, details["url"])
	common.GetAkeylessPtr(&body.PrivilegedUser, details["privileged_user"])
	common.GetAkeylessPtr(&body.Password, details["user_password"])
	common.GetAkeylessPtr(&body.AdministrativePort, details["administrative_port"])
	common.GetAkeylessPtr(&body.AuthorizationPort, details["authorization_port"])

	_, resp, err := client.CreatePingTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create ping target for test", resp, err))
}

func CreateRabbitMqTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateRabbitMQTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.RabbitmqServerUser, details["server_user"])
	common.GetAkeylessPtr(&body.RabbitmqServerPassword, details["server_password"])
	common.GetAkeylessPtr(&body.RabbitmqServerUri, details["server_uri"])

	_, resp, err := client.CreateRabbitMQTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create rabbitmq target for test", resp, err))
}

func CreateSalesforceTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateSalesforceTarget{
		Name:      name,
		Token:     &token,
		AuthFlow:  details["auth_flow"].(string),
		Email:     details["username"].(string),
		TenantUrl: details["tenant_url"].(string),
		ClientId:  details["client_id"].(string),
	}
	common.GetAkeylessPtr(&body.Password, details["password"])
	common.GetAkeylessPtr(&body.ClientSecret, details["client_secret"])
	common.GetAkeylessPtr(&body.SecurityToken, details["security_token"])

	_, resp, err := client.CreateSalesforceTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create salesforce target for test", resp, err))
}

func CreateSshTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateSSHTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.SshUsername, details["username"])
	common.GetAkeylessPtr(&body.SshPassword, details["password"])
	common.GetAkeylessPtr(&body.Host, details["host"])
	common.GetAkeylessPtr(&body.Port, details["port"])
	common.GetAkeylessPtr(&body.PrivateKey, details["private_key"])
	common.GetAkeylessPtr(&body.PrivateKeyPassword, details["private_key_password"])

	_, resp, err := client.CreateSSHTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create ssh target for test", resp, err))
}

func CreateWebTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateWebTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Url, details["url"])

	_, resp, err := client.CreateWebTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create web target for test", resp, err))
}

func CreateWindowsTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateWindowsTarget{
		Name:     name,
		Token:    &token,
		Username: details["username"].(string),
		Password: details["password"].(string),
		Hostname: details["hostname"].(string),
	}
	common.GetAkeylessPtr(&body.Port, details["port"])
	common.GetAkeylessPtr(&body.Domain, details["domain"])
	common.GetAkeylessPtr(&body.Certificate, details["certificate"])
	common.GetAkeylessPtr(&body.UseTls, details["use_tls"])

	_, resp, err := client.CreateWindowsTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create windows target for test", resp, err))
}

func CreateZeroSslTarget(t *testing.T, name string, details map[string]any) {
	client, token, err := GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateZeroSSLTarget{
		Name:         name,
		Token:        &token,
		ApiKey:       details["api_key"].(string),
		ImapUsername: details["imap_username"].(string),
		ImapPassword: details["imap_password"].(string),
		ImapFqdn:     details["imap_fqdn"].(string),
	}
	common.GetAkeylessPtr(&body.ImapPort, details["imap_port"])
	common.GetAkeylessPtr(&body.ImapTargetEmail, details["validation_email"])
	common.GetAkeylessPtr(&body.Timeout, details["timeout"])

	_, resp, err := client.CreateZeroSSLTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create zerossl target for test", resp, err))
}
