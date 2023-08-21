package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGetTargetDetails() *schema.Resource {
	return &schema.Resource{
		Description: "Get target details data source",
		Read:        dataSourceGetTargetDetailsRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"target_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Target version",
			},
			"show_versions": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Include all target versions in reply",
				Default:     "false",
			},
			"value": {
				Type:     schema.TypeMap,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceGetTargetDetailsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetVersion := d.Get("target_version").(int)
	showVersions := d.Get("show_versions").(bool)

	body := akeyless.GetTargetDetails{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetVersion, targetVersion)
	common.GetAkeylessPtr(&body.ShowVersions, showVersions)

	rOut, res, err := client.GetTargetDetails(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't get target details: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get target details: %v", err)
	}
	if rOut.Value == nil {
		return fmt.Errorf("can't get target details: empty details")
	}

	targetType, err := getTargetType(rOut.Target)
	if err != nil {
		return err
	}

	err = setTargetDetailsByType(d, rOut.Value, targetType)
	if err != nil {
		return err
	}

	d.SetId(name)
	return nil
}

func getTargetType(targetOut *akeyless.Target) (string, error) {

	if targetOut == nil {
		return "", errors.New("empty target")
	}

	targetType := targetOut.TargetType
	if targetType == nil {
		return "", errors.New("unknown target type")
	}
	return *targetType, nil
}

func setTargetDetailsByType(d *schema.ResourceData, details *akeyless.TargetTypeDetailsInput, targetType string) error {
	value, err := extractTargetDetailsByType(details, targetType)
	if err != nil {
		return err
	}

	err = d.Set("value", value)
	if err != nil {
		return err
	}
	return nil
}

func extractTargetDetailsByType(details *akeyless.TargetTypeDetailsInput, targetType string) (map[string]string, error) {
	switch {
	case details.ArtifactoryTargetDetails != nil:
		return extractArtifactoryTargetDetails(details.ArtifactoryTargetDetails)
	case details.AwsTargetDetails != nil:
		return extractAwsTargetDetails(details.AwsTargetDetails)
	case details.AzureTargetDetails != nil:
		return extractAzureTargetDetails(details.AzureTargetDetails)
	case details.ChefTargetDetails != nil:
		return extractChefTargetDetails(details.ChefTargetDetails)
	case details.CustomTargetDetails != nil:
		return extractCustomTargetDetails(details.CustomTargetDetails)
	case details.DbTargetDetails != nil && targetType != "mongodb":
		return extractDbTargetDetails(details.DbTargetDetails)
	case details.DockerhubTargetDetails != nil:
		return extractDockerhubTargetDetails(details.DockerhubTargetDetails)
	case details.EksTargetDetails != nil:
		return extractEksTargetDetails(details.EksTargetDetails)
	case details.GcpTargetDetails != nil:
		return extractGcpTargetDetails(details.GcpTargetDetails)
	case details.GithubTargetDetails != nil:
		return extractGithubTargetDetails(details.GithubTargetDetails)
	case details.GkeTargetDetails != nil:
		return extractGkeTargetDetails(details.GkeTargetDetails)
	case details.GlobalsignAtlasTargetDetails != nil:
		return extractGlobalsignAtlasTargetDetails(details.GlobalsignAtlasTargetDetails)
	case details.GlobalsignTargetDetails != nil:
		return extractGlobalsignTargetDetails(details.GlobalsignTargetDetails)
	case details.LdapTargetDetails != nil:
		return extractLdapTargetDetails(details.LdapTargetDetails)
	case details.LinkedTargetDetails != nil:
		return extractLinkedTargetDetails(details.LinkedTargetDetails)
	case details.MongoDbTargetDetails != nil:
		return extractMongoDbTargetDetails(details.MongoDbTargetDetails)
	case details.NativeK8sTargetDetails != nil:
		return extractNativeK8sTargetDetails(details.NativeK8sTargetDetails)
	case details.PingTargetDetails != nil:
		return extractPingTargetDetails(details.PingTargetDetails)
	case details.RabbitMqTargetDetails != nil:
		return extractRabbitMqTargetDetails(details.RabbitMqTargetDetails)
	case details.SalesforceTargetDetails != nil:
		return extractSalesforceTargetDetails(details.SalesforceTargetDetails)
	case details.SshTargetDetails != nil:
		return extractSshTargetDetails(details.SshTargetDetails)
	case details.VenafiTargetDetails != nil:
		return extractVenafiTargetDetails(details.VenafiTargetDetails)
	case details.WebTargetDetails != nil:
		return extractWebTargetDetails(details.WebTargetDetails)
	case details.WindowsTargetDetails != nil:
		return extractWindowsTargetDetails(details.WindowsTargetDetails)
	case details.ZerosslTargetDetails != nil:
		return extractZerosslTargetDetails(details.ZerosslTargetDetails)
	default:
		return nil, fmt.Errorf("can't get target details: unknown target type")
	}
}

func extractArtifactoryTargetDetails(details *akeyless.ArtifactoryTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.ArtifactoryAdminUsername != nil {
		m["admin_name"] = *details.ArtifactoryAdminUsername
	}
	if details.ArtifactoryAdminApikey != nil {
		m["admin_pwd"] = *details.ArtifactoryAdminApikey
	}
	if details.ArtifactoryBaseUrl != nil {
		m["base_url"] = *details.ArtifactoryBaseUrl
	}

	value, err := buildTargetDetailsVal(m, "artifactory_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractAwsTargetDetails(details *akeyless.AWSTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.AwsAccessKeyId != nil {
		m["access_key_id"] = *details.AwsAccessKeyId
	}
	if details.AwsSecretAccessKey != nil {
		m["access_key"] = *details.AwsSecretAccessKey
	}
	if details.AwsSessionToken != nil {
		m["session_token"] = *details.AwsSessionToken
	}
	if details.AwsRegion != nil {
		m["region"] = *details.AwsRegion
	}
	if details.UseGwCloudIdentity != nil {
		m["use_gw_cloud_identity"] = *details.UseGwCloudIdentity
	}

	value, err := buildTargetDetailsVal(m, "aws_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractAzureTargetDetails(details *akeyless.AzureTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.AzureClientId != nil {
		m["client_id"] = *details.AzureClientId
	}
	if details.AzureTenantId != nil {
		m["tenant_id"] = *details.AzureTenantId
	}
	if details.AzureClientSecret != nil {
		m["client_secret"] = *details.AzureClientSecret
	}
	if details.AzureSubscriptionId != nil {
		m["subscription_id"] = *details.AzureSubscriptionId
	}
	if details.AzureResourceGroupName != nil {
		m["resource_group_name"] = *details.AzureResourceGroupName
	}
	if details.AzureResourceName != nil {
		m["resource_name"] = *details.AzureResourceName
	}
	if details.UseGwCloudIdentity != nil {
		m["use_gw_cloud_identity"] = *details.UseGwCloudIdentity
	}

	value, err := buildTargetDetailsVal(m, "azure_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractChefTargetDetails(details *akeyless.ChefTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.ChefServerUsername != nil {
		m["server_username"] = *details.ChefServerUsername
	}
	if details.ChefServerKey != nil {
		m["server_key"] = *details.ChefServerKey
	}
	if details.ChefServerUrl != nil {
		m["server_url"] = *details.ChefServerUrl
	}
	if details.ChefServerHostName != nil {
		m["server_host_name"] = *details.ChefServerHostName
	}
	if details.ChefServerPort != nil {
		m["server_port"] = *details.ChefServerPort
	}
	if details.ChefSkipSsl != nil {
		m["skip_ssl"] = *details.ChefSkipSsl
	}

	value, err := buildTargetDetailsVal(m, "chef_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractCustomTargetDetails(details *akeyless.CustomTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Payload != nil {
		m["custom_payload"] = *details.Payload
	}

	value, err := buildTargetDetailsVal(m, "custom_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractDbTargetDetails(details *akeyless.DbTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.DbUserName != nil {
		m["user_name"] = *details.DbUserName
	}
	if details.DbPwd != nil {
		m["pwd"] = *details.DbPwd
	}
	if details.DbHostName != nil {
		m["host"] = *details.DbHostName
	}
	if details.DbPort != nil {
		m["port"] = *details.DbPort
	}
	if details.DbName != nil {
		m["db_name"] = *details.DbName
	}
	if details.SfAccount != nil {
		m["sf_account"] = *details.SfAccount
	}
	if details.DbPrivateKey != nil {
		m["private_key"] = *details.DbPrivateKey
	}
	if details.DbPrivateKeyPassphrase != nil {
		m["private_key_passphrase"] = *details.DbPrivateKeyPassphrase
	}
	if details.DbServerCertificates != nil {
		m["server_certificates"] = *details.DbServerCertificates
	}
	if details.DbServerName != nil {
		m["server_name"] = *details.DbServerName
	}
	if details.SslConnectionMode != nil {
		m["ssl_connection_mode"] = *details.SslConnectionMode
	}
	if details.SslConnectionCertificate != nil {
		m["ssl_connection_certificate"] = *details.SslConnectionCertificate
	}

	value, err := buildTargetDetailsVal(m, "db_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractDockerhubTargetDetails(details *akeyless.DockerhubTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.UserName != nil {
		m["username"] = *details.UserName
	}
	if details.Password != nil {
		m["password"] = *details.Password
	}

	value, err := buildTargetDetailsVal(m, "dockerhub_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractEksTargetDetails(details *akeyless.EKSTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.EksAccessKeyId != nil {
		m["access_key_id"] = *details.EksAccessKeyId
	}
	if details.EksSecretAccessKey != nil {
		m["access_key"] = *details.EksSecretAccessKey
	}
	if details.EksClusterName != nil {
		m["cluster_name"] = *details.EksClusterName
	}
	if details.EksClusterEndpoint != nil {
		m["cluster_endpoint"] = *details.EksClusterEndpoint
	}
	if details.EksClusterCaCertificate != nil {
		m["cluster_ca_cert"] = *details.EksClusterCaCertificate
	}
	if details.EksRegion != nil {
		m["region"] = *details.EksRegion
	}
	if details.UseGwCloudIdentity != nil {
		m["use_gw_cloud_identity"] = *details.UseGwCloudIdentity
	}

	value, err := buildTargetDetailsVal(m, "eks_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGcpTargetDetails(details *akeyless.GcpTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.GcpServiceAccountKey != nil {
		m["gcp_service_account_key"] = *details.GcpServiceAccountKey
	}
	if details.GcpServiceAccountKeyBase64 != nil {
		m["gcp_service_account_key_base64"] = *details.GcpServiceAccountKeyBase64
	}
	if details.UseGwCloudIdentity != nil {
		m["use_gw_cloud_identity"] = *details.UseGwCloudIdentity
	}

	value, err := buildTargetDetailsVal(m, "gcp_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGithubTargetDetails(details *akeyless.GithubTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.GithubAppId != nil {
		m["app_id"] = *details.GithubAppId
	}
	if details.GithubAppPrivateKey != nil {
		m["app_private_key"] = *details.GithubAppPrivateKey
	}
	if details.GithubBaseUrl != nil {
		m["base_url"] = *details.GithubBaseUrl
	}

	value, err := buildTargetDetailsVal(m, "github_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGkeTargetDetails(details *akeyless.GKETargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.GkeClusterName != nil {
		m["cluster_name"] = *details.GkeClusterName
	}
	if details.GkeClusterEndpoint != nil {
		m["cluster_endpoint"] = *details.GkeClusterEndpoint
	}
	if details.GkeClusterCaCertificate != nil {
		m["cluster_ca_cert"] = *details.GkeClusterCaCertificate
	}
	if details.GkeServiceAccountName != nil {
		m["service_account_email"] = *details.GkeServiceAccountName
	}
	if details.GkeServiceAccountKey != nil {
		m["service_account_key"] = *details.GkeServiceAccountKey
	}
	if details.UseGwCloudIdentity != nil {
		m["use_gw_cloud_identity"] = *details.UseGwCloudIdentity
	}

	value, err := buildTargetDetailsVal(m, "gke_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGlobalsignAtlasTargetDetails(details *akeyless.GlobalSignAtlasTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.ApiKey != nil {
		m["api_key"] = *details.ApiKey
	}
	if details.ApiSecret != nil {
		m["api_secret"] = *details.ApiSecret
	}
	if details.MtlsCert != nil {
		m["mutual_tls_cert"] = *details.MtlsCert
	}
	if details.MtlsKey != nil {
		m["mutual_tls_key"] = *details.MtlsKey
	}
	if details.Timeout != nil {
		m["timeout"] = *details.Timeout
	}

	value, err := buildTargetDetailsVal(m, "globalsign_atlas_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGlobalsignTargetDetails(details *akeyless.GlobalSignGCCTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Username != nil {
		m["username"] = *details.Username
	}
	if details.Password != nil {
		m["password"] = *details.Password
	}
	if details.ProfileId != nil {
		m["profile_id"] = *details.ProfileId
	}
	if details.FirstName != nil {
		m["contact_first_name"] = *details.FirstName
	}
	if details.LastName != nil {
		m["contact_last_name"] = *details.LastName
	}
	if details.Phone != nil {
		m["contact_phone"] = *details.Phone
	}
	if details.Email != nil {
		m["contact_email"] = *details.Email
	}
	if details.Timeout != nil {
		m["timeout"] = *details.Timeout
	}

	value, err := buildTargetDetailsVal(m, "globalsign_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractLdapTargetDetails(details *akeyless.LdapTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.LdapUrl != nil {
		m["url"] = *details.LdapUrl
	}
	if details.LdapBindDn != nil {
		m["bind_dn"] = *details.LdapBindDn
	}
	if details.LdapBindPassword != nil {
		m["bind_password"] = *details.LdapBindPassword
	}
	if details.LdapTokenExpiration != nil {
		m["token_expiration_in_sec"] = *details.LdapTokenExpiration
	}
	if details.LdapAudience != nil {
		m["audience"] = *details.LdapAudience
	}
	if details.LdapCertificate != nil {
		m["certificate"] = *details.LdapCertificate
	}
	if details.ImplementationType != nil {
		m["implementation_type"] = *details.ImplementationType
	}

	value, err := buildTargetDetailsVal(m, "ldap_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractLinkedTargetDetails(details *akeyless.LinkedTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Hosts != nil {
		m["hosts"] = fmt.Sprintf("%v", *details.Hosts)
	}

	value, err := buildTargetDetailsVal(m, "linked_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractMongoDbTargetDetails(details *akeyless.MongoDBTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.MongodbDbName != nil {
		m["db_name"] = *details.MongodbDbName
	}
	if details.MongodbUriConnection != nil {
		m["uri_connection"] = *details.MongodbUriConnection
	}
	if details.MongodbUsername != nil {
		m["username"] = *details.MongodbUsername
	}
	if details.MongodbPassword != nil {
		m["password"] = *details.MongodbPassword
	}
	if details.MongodbHostPort != nil {
		m["host_port"] = *details.MongodbHostPort
	}
	if details.MongodbDefaultAuthDb != nil {
		m["default_auth_db"] = *details.MongodbDefaultAuthDb
	}
	if details.MongodbUriOptions != nil {
		m["uri_options"] = *details.MongodbUriOptions
	}
	if details.MongodbAtlasProjectId != nil {
		m["atlas_project_id"] = *details.MongodbAtlasProjectId
	}
	if details.MongodbAtlasApiPublicKey != nil {
		m["atlas_api_public_key"] = *details.MongodbAtlasApiPublicKey
	}
	if details.MongodbAtlasApiPrivateKey != nil {
		m["atlas_api_private_key"] = *details.MongodbAtlasApiPrivateKey
	}
	if details.MongodbIsAtlas != nil {
		m["is_atlas"] = *details.MongodbIsAtlas
	}

	value, err := buildTargetDetailsVal(m, "mongo_db_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractNativeK8sTargetDetails(details *akeyless.NativeK8sTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.K8sClusterEndpoint != nil {
		m["cluster_endpoint"] = *details.K8sClusterEndpoint
	}
	if details.K8sClusterCaCertificate != nil {
		m["cluster_ca_cert"] = *details.K8sClusterCaCertificate
	}
	if details.K8sBearerToken != nil {
		m["bearer_token"] = *details.K8sBearerToken
	}
	if details.UseGwServiceAccount != nil {
		m["use_gw_cloud_identity"] = *details.UseGwServiceAccount
	}

	value, err := buildTargetDetailsVal(m, "native_k8s_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractPingTargetDetails(details *akeyless.PingTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.PingUrl != nil {
		m["url"] = *details.PingUrl
	}
	if details.PrivilegedUser != nil {
		m["privileged_user"] = *details.PrivilegedUser
	}
	if details.UserPassword != nil {
		m["user_password"] = *details.UserPassword
	}
	if details.AdministrativePort != nil {
		m["administrative_port"] = *details.AdministrativePort
	}
	if details.AuthorizationPort != nil {
		m["authorization_port"] = *details.AuthorizationPort
	}

	value, err := buildTargetDetailsVal(m, "ping_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractRabbitMqTargetDetails(details *akeyless.RabbitMQTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.RabbitmqServerUser != nil {
		m["server_user"] = *details.RabbitmqServerUser
	}
	if details.RabbitmqServerPassword != nil {
		m["server_password"] = *details.RabbitmqServerPassword
	}
	if details.RabbitmqServerUri != nil {
		m["server_uri"] = *details.RabbitmqServerUri
	}

	value, err := buildTargetDetailsVal(m, "rabbit_mq_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractSalesforceTargetDetails(details *akeyless.SalesforceTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.AuthFlow != nil {
		m["auth_flow"] = *details.AuthFlow
	}
	if details.UserName != nil {
		m["username"] = *details.UserName
	}
	if details.Password != nil {
		m["password"] = *details.Password
	}
	if details.TenantUrl != nil {
		m["tenant_url"] = *details.TenantUrl
	}
	if details.ClientId != nil {
		m["client_id"] = *details.ClientId
	}
	if details.ClientSecret != nil {
		m["client_secret"] = *details.ClientSecret
	}
	if details.SecurityToken != nil {
		m["security_token"] = *details.SecurityToken
	}
	if details.CaCertName != nil {
		m["ca_cert_name"] = *details.CaCertName
	}
	// if details.AppPrivateKey != nil {
	// 	m["app_private_key"] = *details.AppPrivateKey
	// }
	// if details.CaCertData != nil {
	// 	m["ca_cert_data"] = *details.CaCertData
	// }

	value, err := buildTargetDetailsVal(m, "salesforce_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractSshTargetDetails(details *akeyless.SSHTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Username != nil {
		m["username"] = *details.Username
	}
	if details.Password != nil {
		m["password"] = *details.Password
	}
	if details.Host != nil {
		m["host"] = *details.Host
	}
	if details.Port != nil {
		m["port"] = *details.Port
	}
	if details.PrivateKey != nil {
		m["private_key"] = *details.PrivateKey
	}
	if details.PrivateKeyPassword != nil {
		m["private_key_password"] = *details.PrivateKeyPassword
	}

	value, err := buildTargetDetailsVal(m, "ssh_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractVenafiTargetDetails(details *akeyless.VenafiTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.VenafiApiKey != nil {
		m["api_key"] = *details.VenafiApiKey
	}
	if details.VenafiZone != nil {
		m["zone"] = *details.VenafiZone
	}
	if details.VenafiBaseUrl != nil {
		m["base_url"] = *details.VenafiBaseUrl
	}
	if details.VenafiTppAccessToken != nil {
		m["tpp_access_token"] = *details.VenafiTppAccessToken
	}
	if details.VenafiTppRefreshToken != nil {
		m["tpp_refresh_token"] = *details.VenafiTppRefreshToken
	}
	if details.VenafiTppClientId != nil {
		m["tpp_client_id"] = *details.VenafiTppClientId
	}
	if details.VenafiUseTpp != nil {
		m["use_tpp"] = *details.VenafiUseTpp
	}

	value, err := buildTargetDetailsVal(m, "venafi_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractWebTargetDetails(details *akeyless.WebTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Url != nil {
		m["url"] = *details.Url
	}

	value, err := buildTargetDetailsVal(m, "web_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractWindowsTargetDetails(details *akeyless.WindowsTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Username != nil {
		m["username"] = *details.Username
	}
	if details.Password != nil {
		m["password"] = *details.Password
	}
	if details.Hostname != nil {
		m["hostname"] = *details.Hostname
	}
	if details.Port != nil {
		m["port"] = *details.Port
	}
	if details.DomainName != nil {
		m["domain"] = *details.DomainName
	}
	if details.Certificate != nil {
		m["certificate"] = *details.Certificate
	}
	if details.UseTls != nil {
		m["use_tls"] = *details.UseTls
	}

	value, err := buildTargetDetailsVal(m, "windows_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractZerosslTargetDetails(details *akeyless.ZeroSSLTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.ApiKey != nil {
		m["api_key"] = *details.ApiKey
	}
	if details.ImapUser != nil {
		m["imap_username"] = *details.ImapUser
	}
	if details.ImapPassword != nil {
		m["imap_password"] = *details.ImapPassword
	}
	if details.ImapFqdn != nil {
		m["imap_fqdn"] = *details.ImapFqdn
	}
	if details.ImapPort != nil {
		m["imap_port"] = *details.ImapPort
	}
	if details.ValidationEmail != nil {
		m["validation_email"] = *details.ValidationEmail
	}
	if details.Timeout != nil {
		m["timeout"] = *details.Timeout
	}

	value, err := buildTargetDetailsVal(m, "zerossl_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func buildTargetDetailsVal(m map[string]interface{}, targetType string) (map[string]string, error) {

	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	return map[string]string{targetType: string(b)}, nil
}
