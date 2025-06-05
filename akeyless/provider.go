package akeyless

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/aws"
	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/azure"
	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/gcp"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// default: public API Gateway
const publicApi = "https://api.akeyless.io"

// Provider returns Akeyless Terraform provider
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_gateway_address": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_GATEWAY", publicApi),
				Description: "Origin URL of the API Gateway server. This is a URL with a scheme, a hostname and a port.",
			},
			"api_key_login":  apiKeyLoginSchema,
			"aws_iam_login":  awsIamLoginSchema,
			"gcp_login":      gcpLoginSchema,
			"azure_ad_login": azureAdLoginSchema,
			"jwt_login":      jwtLoginSchema,
			"email_login":    emailLoginSchema,
			"uid_login":      uidLoginSchema,
			"cert_login":     certLoginSchema,
			"token_login":    tokenLoginSchema,
		},
		//ConfigureFunc: configureProvider,
		ConfigureContextFunc: configureProvider,
		ResourcesMap: map[string]*schema.Resource{
			"akeyless_classic_key":                             resourceClassicKey(),
			"akeyless_dfc_key":                                 resourceDfcKey(),
			"akeyless_static_secret":                           resourceStaticSecret(),
			"akeyless_pki_cert_issuer":                         resourcePKICertIssuer(),
			"akeyless_ssh_cert_issuer":                         resourceSSHCertIssuer(),
			"akeyless_auth_method":                             resourceAuthMethod(),
			"akeyless_auth_method_api_key":                     resourceAuthMethodApiKey(),
			"akeyless_auth_method_aws_iam":                     resourceAuthMethodAwsIam(),
			"akeyless_auth_method_azure_ad":                    resourceAuthMethodAzureAd(),
			"akeyless_auth_method_cert":                        resourceAuthMethodCert(),
			"akeyless_auth_method_gcp":                         resourceAuthMethodGcp(),
			"akeyless_auth_method_k8s":                         resourceAuthMethodK8s(),
			"akeyless_auth_method_ldap":                        resourceAuthMethodLdap(),
			"akeyless_auth_method_oauth2":                      resourceAuthMethodOauth2(),
			"akeyless_auth_method_oidc":                        resourceAuthMethodOidc(),
			"akeyless_auth_method_saml":                        resourceAuthMethodSaml(),
			"akeyless_auth_method_universal_identity":          resourceAuthMethodUniversalIdentity(),
			"akeyless_certificate":                             resourceCertificate(),
			"akeyless_role":                                    resourceRole(),
			"akeyless_producer_aws":                            resourceProducerAws(),
			"akeyless_gateway_allowed_access":                  resourceGatewayAllowedAccess(),
			"akeyless_gateway_cache":                           resourceGatewayUpdateCache(),
			"akeyless_gateway_defaults":                        resourceGatewayUpdateDefaults(),
			"akeyless_gateway_log_forwarding_aws_s3":           resourceGatewayUpdateLogForwardingAwsS3(),
			"akeyless_gateway_log_forwarding_azure_analytics":  resourceGatewayUpdateLogForwardingAzureAnalytics(),
			"akeyless_gateway_log_forwarding_datadog":          resourceGatewayUpdateLogForwardingDatadog(),
			"akeyless_gateway_log_forwarding_elasticsearch":    resourceGatewayUpdateLogForwardingElasticsearch(),
			"akeyless_gateway_log_forwarding_google_chronicle": resourceGatewayUpdateLogForwardingGoogleChronicle(),
			"akeyless_gateway_log_forwarding_logstash":         resourceGatewayUpdateLogForwardingLogstash(),
			"akeyless_gateway_log_forwarding_logz_io":          resourceGatewayUpdateLogForwardingLogzIo(),
			"akeyless_gateway_log_forwarding_splunk":           resourceGatewayUpdateLogForwardingSplunk(),
			"akeyless_gateway_log_forwarding_stdout":           resourceGatewayUpdateLogForwardingStdout(),
			"akeyless_gateway_log_forwarding_sumologic":        resourceGatewayUpdateLogForwardingSumologic(),
			"akeyless_gateway_log_forwarding_syslog":           resourceGatewayUpdateLogForwardingSyslog(),
			"akeyless_gateway_remote_access":                   resourceGatewayUpdateRemoteAccess(),
			"akeyless_gateway_remote_access_rdp_recording":     resourceGatewayUpdateRemoteAccessRdpRecording(),
			"akeyless_event_forwarder_email":                   resourceEventForwarderEmail(),
			"akeyless_event_forwarder_service_now":             resourceEventForwarderServiceNow(),
			"akeyless_event_forwarder_slack":                   resourceEventForwarderSlack(),
			"akeyless_event_forwarder_webhook":                 resourceEventForwarderWebhook(),
			"akeyless_producer_custom":                         resourceProducerCustom(),
			"akeyless_producer_rdp":                            resourceProducerRdp(),
			"akeyless_producer_mongo":                          resourceProducerMongo(),
			"akeyless_producer_mssql":                          resourceProducerMssql(),
			"akeyless_producer_mysql":                          resourceProducerMysql(),
			"akeyless_producer_oracle":                         resourceProducerOracle(),
			"akeyless_producer_postgres":                       resourceProducerPostgresql(),
			"akeyless_producer_redshift":                       resourceProducerRedshift(),
			"akeyless_producer_gcp":                            resourceProducerGcp(),
			"akeyless_producer_gke":                            resourceProducerGke(),
			"akeyless_producer_github":                         resourceProducerGithub(),
			"akeyless_producer_eks":                            resourceProducerEks(),
			"akeyless_producer_cassandra":                      resourceProducerCassandra(),
			"akeyless_producer_azure":                          resourceProducerAzure(),
			"akeyless_producer_artifactory":                    resourceProducerArtifactory(),
			"akeyless_producer_k8s":                            resourceProducerK8s(),
			"akeyless_dynamic_secret_artifactory":              resourceDynamicSecretArtifactory(),
			"akeyless_dynamic_secret_aws":                      resourceDynamicSecretAws(),
			"akeyless_dynamic_secret_azure":                    resourceDynamicSecretAzure(),
			"akeyless_dynamic_secret_cassandra":                resourceDynamicSecretCassandra(),
			"akeyless_dynamic_secret_custom":                   resourceDynamicSecretCustom(),
			"akeyless_dynamic_secret_eks":                      resourceDynamicSecretEks(),
			"akeyless_dynamic_secret_gcp":                      resourceDynamicSecretGcp(),
			"akeyless_dynamic_secret_github":                   resourceDynamicSecretGithub(),
			"akeyless_dynamic_secret_gitlab":                   resourceDynamicSecretGitlab(),
			"akeyless_dynamic_secret_gke":                      resourceDynamicSecretGke(),
			"akeyless_dynamic_secret_k8s":                      resourceDynamicSecretK8s(),
			"akeyless_dynamic_secret_mongodb":                  resourceDynamicSecretMongo(),
			"akeyless_dynamic_secret_mssql":                    resourceDynamicSecretMssql(),
			"akeyless_dynamic_secret_mysql":                    resourceDynamicSecretMysql(),
			"akeyless_dynamic_secret_oracle":                   resourceDynamicSecretOracle(),
			"akeyless_dynamic_secret_postgresql":               resourceDynamicSecretPostgresql(),
			"akeyless_dynamic_secret_rdp":                      resourceDynamicSecretRdp(),
			"akeyless_dynamic_secret_redshift":                 resourceDynamicSecretRedshift(),
			"akeyless_rotated_secret":                          resourceRotatedSecret(),
			"akeyless_rotated_secret_aws":                      resourceRotatedSecretAws(),
			"akeyless_rotated_secret_azure":                    resourceRotatedSecretAzure(),
			"akeyless_rotated_secret_cassandra":                resourceRotatedSecretCassandra(),
			"akeyless_rotated_secret_custom":                   resourceRotatedSecretCustom(),
			"akeyless_rotated_secret_dockerhub":                resourceRotatedSecretDockerHub(),
			"akeyless_rotated_secret_gcp":                      resourceRotatedSecretGcp(),
			"akeyless_rotated_secret_hanadb":                   resourceRotatedSecretHanaDb(),
			"akeyless_rotated_secret_ldap":                     resourceRotatedSecretLdap(),
			"akeyless_rotated_secret_mongodb":                  resourceRotatedSecretMongo(),
			"akeyless_rotated_secret_mssql":                    resourceRotatedSecretMsSql(),
			"akeyless_rotated_secret_mysql":                    resourceRotatedSecretMySql(),
			"akeyless_rotated_secret_oracle":                   resourceRotatedSecretOracle(),
			"akeyless_rotated_secret_postgresql":               resourceRotatedSecretPostgreSql(),
			"akeyless_rotated_secret_redis":                    resourceRotatedSecretRedis(),
			"akeyless_rotated_secret_redshift":                 resourceRotatedSecretRedshift(),
			"akeyless_rotated_secret_snowflake":                resourceRotatedSecretSnowflake(),
			"akeyless_rotated_secret_ssh":                      resourceRotatedSecretSsh(),
			"akeyless_rotated_secret_windows":                  resourceRotatedSecretWindows(),
			"akeyless_rotated_secret_sync":                     resourceRotatedSecretSync(),
			"akeyless_target_artifactory":                      resourceArtifactoryTarget(),
			"akeyless_target_aws":                              resourceAwsTarget(),
			"akeyless_target_azure":                            resourceAzureTarget(),
			"akeyless_target_db":                               resourceDbTarget(),
			"akeyless_target_eks":                              resourceEksTarget(),
			"akeyless_target_gcp":                              resourceGcpTarget(),
			"akeyless_target_github":                           resourceGithubTarget(),
			"akeyless_target_gitlab":                           resourceGitlabTarget(),
			"akeyless_target_gke":                              resourceGkeTarget(),
			"akeyless_target_globalsign":                       resourceGlobalsignTarget(),
			"akeyless_target_k8s":                              resourceK8sTarget(),
			"akeyless_target_linked":                           resourceLinkedTarget(),
			"akeyless_target_rabbit":                           resourceRabbitmqTarget(),
			"akeyless_target_ssh":                              resourceSSHTarget(),
			"akeyless_target_web":                              resourceWebTarget(),
			"akeyless_target_windows":                          resourceWindowsTarget(),
			"akeyless_target_zerossl":                          resourceZerosslTarget(),
			"akeyless_k8s_auth_config":                         resourceK8sAuthConfig(),
			"akeyless_associate_role_auth_method":              resourceAssocRoleAm(),
			"akeyless_tokenizer":                               resourceTokenizer(),
			"akeyless_usc":                                     resourceUsc(),
			"akeyless_usc_secret":                              resourceUscSecret(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"akeyless_auth":               dataSourceAuth(),
			"akeyless_static_secret":      dataSourceStaticSecret(),
			"akeyless_secret":             dataSourceSecret(),
			"akeyless_auth_method":        dataSourceAuthMethod(),
			"akeyless_certificate":        dataSourceCertificate(),
			"akeyless_dynamic_secret":     dataSourceDynamicSecret(),
			"akeyless_role":               dataSourceRole(),
			"akeyless_k8s_auth_config":    dataSourceGatewayGetK8sAuthConfig(),
			"akeyless_kube_exec_creds":    dataSourceGetKubeExecCreds(),
			"akeyless_producer_tmp_creds": dataSourceGatewayGetProducerTmpCreds(),
			"akeyless_rotated_secret":     dataSourceGetRotatedSecretValue(),
			"akeyless_rsa_pub":            dataSourceGetRSAPublic(),
			"akeyless_csr":                dataSourceGenerateCsr(),
			"akeyless_pki_certificate":    dataSourceGetPKICertificate(),
			"akeyless_ssh_certificate":    dataSourceGetSSHCertificate(),
			"akeyless_tags":               dataSourceGetTags(),
			"akeyless_target_details":     dataSourceGetTargetDetails(),
			"akeyless_target":             dataSourceGetTarget(),
			"akeyless_tokenize":           dataSourceTokenize(),
			"akeyless_detokenize":         dataSourceDetokenize(),
		},
	}
}

func getProviderToken(ctx context.Context, d *schema.ResourceData, client *akeyless_api.V2ApiService) (string, error) {

	tokenLogin := d.Get("token_login").([]interface{})
	if len(tokenLogin) > 0 {
		return extractTokenFromInput(tokenLogin)
	}
	return getTokenByAuth(ctx, d, client)
}

func extractTokenFromInput(tokenLogin []interface{}) (string, error) {

	if len(tokenLogin) > 1 {
		return "", fmt.Errorf("token_login block may appear only once")
	}

	login, ok := tokenLogin[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("wrong login detais")
	}
	token := login["token"].(string)
	return token, nil
}

func getTokenByAuth(ctx context.Context, d *schema.ResourceData, client *akeyless_api.V2ApiService) (string, error) {

	authBody, err := getAuthInfo(d)
	if err != nil {
		return "", err
	}

	authOut, _, err := client.Auth(ctx).Body(*authBody).Execute()
	if err != nil {
		var apiErr akeyless_api.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			return "", fmt.Errorf("authentication failed: %s", string(apiErr.Body()))
		}
		return "", fmt.Errorf("authentication failed: %w", err)
	}
	return authOut.GetToken(), nil
}

func getAuthInfo(d *schema.ResourceData) (*akeyless_api.Auth, error) {
	login, authType, err := getLoginWithValidation(d)
	if err != nil {
		return nil, err
	}

	authBody := akeyless_api.NewAuthWithDefaults()
	err = setAuthBody(authBody, login, authType)
	if err != nil {
		return nil, err
	}

	return authBody, nil
}

func setAuthBody(authBody *akeyless_api.Auth, loginObj interface{}, authType loginType) error {

	login, ok := loginObj.(map[string]interface{})
	if !ok {
		return fmt.Errorf("wrong login detais")
	}

	switch authType {
	case ApiKeyLogin:
		accessID := login["access_id"].(string)
		accessKey := login["access_key"].(string)
		authBody.AccessId = akeyless_api.PtrString(accessID)
		authBody.AccessKey = akeyless_api.PtrString(accessKey)
		authBody.AccessType = akeyless_api.PtrString(common.ApiKey)
		return nil
	case EmailLogin:
		adminEmail := login["admin_email"].(string)
		adminPassword := login["admin_password"].(string)
		authBody.AdminEmail = akeyless_api.PtrString(adminEmail)
		authBody.AdminPassword = akeyless_api.PtrString(adminPassword)
		authBody.AccessType = akeyless_api.PtrString(common.Password)
		return nil
	case AwsIAMLogin:
		accessID := login["access_id"].(string)
		authBody.AccessId = akeyless_api.PtrString(accessID)
		cloudId, err := aws.GetCloudId()
		if err != nil {
			return fmt.Errorf("require Cloud ID: %v", err.Error())
		}
		authBody.CloudId = akeyless_api.PtrString(cloudId)
		authBody.AccessType = akeyless_api.PtrString(common.AwsIAM)
		return nil
	case GcpIAMLogin:
		accessID := login["access_id"].(string)
		audience := login["audience"].(string)
		authBody.AccessId = akeyless_api.PtrString(accessID)
		authBody.GcpAudience = akeyless_api.PtrString(audience)
		cloudId, err := gcp.GetCloudID(audience)
		if err != nil {
			return fmt.Errorf("require Cloud ID: %v", err.Error())
		}
		authBody.CloudId = akeyless_api.PtrString(cloudId)
		authBody.AccessType = akeyless_api.PtrString(common.Gcp)
		return nil
	case AzureADLogin:
		accessID := login["access_id"].(string)
		authBody.AccessId = akeyless_api.PtrString(accessID)
		cloudId, err := azure.GetCloudId("")
		if err != nil {
			return fmt.Errorf("require Cloud ID: %v", err.Error())
		}
		authBody.CloudId = akeyless_api.PtrString(cloudId)
		authBody.AccessType = akeyless_api.PtrString(common.AzureAD)
		return nil
	case JwtLogin:
		accessID := login["access_id"].(string)
		jwt := login["jwt"].(string)
		authBody.AccessId = akeyless_api.PtrString(accessID)
		authBody.Jwt = akeyless_api.PtrString(jwt)
		authBody.AccessType = akeyless_api.PtrString(common.Jwt)
		return nil
	case UidLogin:
		accessID := login["access_id"].(string)
		uidToken := login["uid_token"].(string)
		authBody.AccessId = akeyless_api.PtrString(accessID)
		authBody.UidToken = akeyless_api.PtrString(uidToken)
		authBody.AccessType = akeyless_api.PtrString(common.Uid)
		return nil
	case CertLogin:
		certFile := login["cert_file_name"].(string)
		keyFile := login["key_file_name"].(string)
		certData := login["cert_data"].(string)
		keyData := login["key_data"].(string)

		if certFile == "" && certData == "" {
			return fmt.Errorf("must provide cert_file_name or cert_data")
		}
		if keyFile == "" && keyData == "" {
			return fmt.Errorf("must provide key_file_name or key_data")
		}

		if certFile != "" {
			data, err := common.ReadAndEncodeFile(certFile)
			if err != nil {
				return fmt.Errorf("failed to read certificate: %v", err)
			}
			certData = data
		}

		if keyFile != "" {
			data, err := common.ReadAndEncodeFile(keyFile)
			if err != nil {
				return fmt.Errorf("failed to read private key: %v", err)
			}
			keyData = data
		}

		accessID := login["access_id"].(string)
		authBody.AccessId = akeyless_api.PtrString(accessID)
		authBody.CertData = akeyless_api.PtrString(certData)
		authBody.KeyData = akeyless_api.PtrString(keyData)
		authBody.AccessType = akeyless_api.PtrString(common.Cert)
		return nil
	default:
		return fmt.Errorf("please choose supported login method: api_key_login/password_login/aws_iam_login/gcp_login/azure_ad_login/jwt_login/uid_login/cert_login/token_login")
	}
}

type providerMeta struct {
	client *akeyless_api.V2ApiService
	token  *string
}

func getLoginWithValidation(d *schema.ResourceData) (interface{}, loginType, error) {

	apiKeyLogin := d.Get("api_key_login").([]interface{})
	if len(apiKeyLogin) > 1 {
		return nil, "", fmt.Errorf("api_key_login block may appear only once")
	}
	if len(apiKeyLogin) == 1 {
		return apiKeyLogin[0], ApiKeyLogin, nil
	}

	emailLogin := d.Get("email_login").([]interface{})
	if len(emailLogin) > 1 {
		return nil, "", fmt.Errorf("email_login block may appear only once")
	}
	if len(emailLogin) == 1 {
		return emailLogin[0], EmailLogin, nil
	}

	awsIAMLogin := d.Get("aws_iam_login").([]interface{})
	if len(awsIAMLogin) > 1 {
		return nil, "", fmt.Errorf("aws_iam_login block may appear only once")
	}
	if len(awsIAMLogin) == 1 {
		return awsIAMLogin[0], AwsIAMLogin, nil
	}

	gcpIAMLogin := d.Get("gcp_login").([]interface{})
	if len(gcpIAMLogin) > 1 {
		return nil, "", fmt.Errorf("gcp_login block may appear only once")
	}
	if len(gcpIAMLogin) == 1 {
		return gcpIAMLogin[0], GcpIAMLogin, nil
	}

	azureADLogin := d.Get("azure_ad_login").([]interface{})
	if len(azureADLogin) > 1 {
		return nil, "", fmt.Errorf("azure_ad_login block may appear only once")
	}
	if len(azureADLogin) == 1 {
		return azureADLogin[0], AzureADLogin, nil
	}

	jwtLogin := d.Get("jwt_login").([]interface{})
	if len(jwtLogin) > 1 {
		return nil, "", fmt.Errorf("jwt_login block may appear only once")
	}
	if len(jwtLogin) == 1 {
		return jwtLogin[0], JwtLogin, nil
	}

	uidLogin := d.Get("uid_login").([]interface{})
	if len(uidLogin) > 1 {
		return nil, "", fmt.Errorf("uid_login block may appear only once")
	}
	if len(uidLogin) == 1 {
		return uidLogin[0], UidLogin, nil
	}

	certLogin := d.Get("cert_login").([]interface{})
	if len(certLogin) > 1 {
		return nil, "", fmt.Errorf("cert_login block may appear only once")
	}
	if len(certLogin) == 1 {
		return certLogin[0], CertLogin, nil
	}

	// if login details not provided, use api-key authentication with id+key from env vars
	if os.Getenv("AKEYLESS_ACCESS_ID") != "" && os.Getenv("AKEYLESS_ACCESS_KEY") != "" {
		login := make(map[string]interface{})
		login["access_id"] = os.Getenv("AKEYLESS_ACCESS_ID")
		login["access_key"] = os.Getenv("AKEYLESS_ACCESS_KEY")

		return login, ApiKeyLogin, nil
	}

	return nil, "", fmt.Errorf("please choose supported login method: api_key_login/password_login/aws_iam_login/gcp_login/azure_ad_login/jwt_login/uid_login/cert_login/token_login")
}

func getProviderClient(ctx context.Context, d *schema.ResourceData) *akeyless_api.V2ApiService {
	apiGwAddress := d.Get("api_gateway_address").(string)

	client := akeyless_api.NewAPIClient(&akeyless_api.Configuration{
		Servers: []akeyless_api.ServerConfiguration{
			{
				URL: apiGwAddress,
			},
		},
		DefaultHeader: map[string]string{common.ClientTypeHeader: common.TerraformClientType},
	}).V2Api

	return client
}

func configureProvider(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diagnostic diag.Diagnostics

	client := getProviderClient(ctx, d)

	token, err := getProviderToken(ctx, d, client)
	if err != nil {
		diagnostic = diag.Diagnostics{{Severity: diag.Warning, Summary: err.Error()}}
	}
	return &providerMeta{client: client, token: &token}, diagnostic
}
