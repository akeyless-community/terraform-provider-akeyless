package akeyless

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/aws"
	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/azure"
	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type loginType string

// default: public API Gateway
const publicApi = "https://api.akeyless.io"

const (
	ApiKeyLogin  loginType = "api_key_login"
	AwsIAMLogin  loginType = "aws_iam_login"
	AzureADLogin loginType = "azure_ad_login"
	JwtLogin     loginType = "jwt_login"
	EmailLogin   loginType = "email_login"
	UidLogin     loginType = "uid_login"
	CertLogin    loginType = "cert_login"
)

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
			"api_key_login": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A configuration block, described below, that attempts to authenticate using API-Key.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"access_id": {
							Type:        schema.TypeString,
							Required:    true,
							DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_ACCESS_ID", nil),
						},
						"access_key": {
							Type:        schema.TypeString,
							Required:    true,
							Sensitive:   true,
							DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_ACCESS_KEY", nil),
						},
					},
				},
			},
			"aws_iam_login": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A configuration block, described below, that attempts to authenticate using AWS-IAM authentication credentials.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"access_id": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"azure_ad_login": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A configuration block, described below, that attempts to authenticate using Azure Active Directory authentication.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"access_id": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"jwt_login": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A configuration block, described below, that attempts to authenticate using JWT authentication.  The JWT can be provided as a command line variable or it will be pulled out of an environment variable named AKEYLESS_AUTH_JWT.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"access_id": {
							Type:     schema.TypeString,
							Required: true,
						},
						"jwt": {
							Type:        schema.TypeString,
							Required:    true,
							Sensitive:   true,
							DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_AUTH_JWT", nil),
						},
					},
				},
			},
			"email_login": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A configuration block, described below, that attempts to authenticate using email and password.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"admin_email": {
							Type:        schema.TypeString,
							Required:    true,
							DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_EMAIL", nil),
						},
						"admin_password": {
							Type:        schema.TypeString,
							Required:    true,
							DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_PASSWORD", nil),
						},
					},
				},
			},
			"uid_login": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A configuration block, described below, that attempts to authenticate using Universal Identity authentication.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"access_id": {
							Type:     schema.TypeString,
							Required: true,
						},
						"uid_token": {
							Type:        schema.TypeString,
							Required:    true,
							Sensitive:   true,
							DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_AUTH_UID", nil),
						},
					},
				},
			},
			"cert_login": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A configuration block, described below, that attempts to authenticate using Certificate authentication.  The Certificate and the Private key can be provided as a command line variable or it will be pulled out of an environment variable named AKEYLESS_AUTH_CERT and AKEYLESS_AUTH_KEY.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"access_id": {
							Type:     schema.TypeString,
							Required: true,
						},
						"cert_file_name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"cert_data": {
							Type:        schema.TypeString,
							Optional:    true,
							Sensitive:   true,
							DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_AUTH_CERT", nil),
						},
						"key_file_name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"key_data": {
							Type:        schema.TypeString,
							Optional:    true,
							Sensitive:   true,
							DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_AUTH_KEY", nil),
						},
					},
				},
			},
		},
		//ConfigureFunc: configureProvider,
		ConfigureContextFunc: configureProvider,
		ResourcesMap: map[string]*schema.Resource{
			"akeyless_dfc_key":                        resourceDfcKey(),
			"akeyless_static_secret":                  resourceStaticSecret(),
			"akeyless_pki_cert_issuer":                resourcePKICertIssuer(),
			"akeyless_ssh_cert_issuer":                resourceSSHCertIssuer(),
			"akeyless_auth_method":                    resourceAuthMethod(),
			"akeyless_auth_method_api_key":            resourceAuthMethodApiKey(),
			"akeyless_auth_method_aws_iam":            resourceAuthMethodAwsIam(),
			"akeyless_auth_method_azure_ad":           resourceAuthMethodAzureAd(),
			"akeyless_auth_method_cert":               resourceAuthMethodCert(),
			"akeyless_auth_method_gcp":                resourceAuthMethodGcp(),
			"akeyless_auth_method_k8s":                resourceAuthMethodK8s(),
			"akeyless_auth_method_oauth2":             resourceAuthMethodOauth2(),
			"akeyless_auth_method_oidc":               resourceAuthMethodOidc(),
			"akeyless_auth_method_saml":               resourceAuthMethodSaml(),
			"akeyless_auth_method_universal_identity": resourceAuthMethodUniversalIdentity(),
			"akeyless_role":                           resourceRole(),
			"akeyless_producer_aws":                   resourceProducerAws(),
			"akeyless_gateway_allowed_access":         resourceGatewayAllowedAccess(),
			"akeyless_producer_custom":                resourceProducerCustom(),
			"akeyless_producer_rdp":                   resourceProducerRdp(),
			"akeyless_producer_mongo":                 resourceProducerMongo(),
			"akeyless_producer_mssql":                 resourceProducerMssql(),
			"akeyless_producer_mysql":                 resourceProducerMysql(),
			"akeyless_producer_oracle":                resourceProducerOracle(),
			"akeyless_producer_postgres":              resourceProducerPostgresql(),
			"akeyless_producer_redshift":              resourceProducerRedshift(),
			"akeyless_producer_gcp":                   resourceProducerGcp(),
			"akeyless_producer_gke":                   resourceProducerGke(),
			"akeyless_producer_github":                resourceProducerGithub(),
			"akeyless_producer_eks":                   resourceProducerEks(),
			"akeyless_producer_cassandra":             resourceProducerCassandra(),
			"akeyless_producer_azure":                 resourceProducerAzure(),
			"akeyless_producer_artifactory":           resourceProducerArtifactory(),
			"akeyless_producer_k8s":                   resourceProducerK8s(),
			"akeyless_rotated_secret":                 resourceRotatedSecret(),
			"akeyless_target_artifactory":             resourceArtifactoryTarget(),
			"akeyless_target_aws":                     resourceAwsTarget(),
			"akeyless_target_azure":                   resourceAzureTarget(),
			"akeyless_target_db":                      resourceDbTarget(),
			"akeyless_target_eks":                     resourceEksTarget(),
			"akeyless_target_gcp":                     resourceGcpTarget(),
			"akeyless_target_github":                  resourceGithubTarget(),
			"akeyless_target_gke":                     resourceGkeTarget(),
			"akeyless_target_globalsign":              resourceGlobalsignTarget(),
			"akeyless_target_k8s":                     resourceK8sTarget(),
			"akeyless_target_rabbit":                  resourceRabbitmqTarget(),
			"akeyless_target_ssh":                     resourceSSHTarget(),
			"akeyless_target_web":                     resourceWebTarget(),
			"akeyless_target_zerossl":                 resourceZerosslTarget(),
			"akeyless_k8s_auth_config":                resourceK8sAuthConfig(),
			"akeyless_associate_role_auth_method":     resourceAssocRoleAm(),
			"akeyless_tokenizer":                      resourceTokenizer(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"akeyless_static_secret":      dataSourceStaticSecret(),
			"akeyless_secret":             dataSourceSecret(),
			"akeyless_auth_method":        dataSourceAuthMethod(),
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

func configureProvider(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	apiGwAddress := d.Get("api_gateway_address").(string)

	diagnostic := diag.Diagnostics{{Severity: diag.Error, Summary: ""}}

	authBody, err := getAuthInfo(d)
	if err != nil {
		diagnostic[0].Summary = err.Error()
		return "", diagnostic
	}

	client := akeyless.NewAPIClient(&akeyless.Configuration{
		Servers: []akeyless.ServerConfiguration{
			{
				URL: apiGwAddress,
			},
		},
	}).V2Api

	var apiErr akeyless.GenericOpenAPIError

	authOut, _, err := client.Auth(ctx).Body(*authBody).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			diagnostic[0].Summary = fmt.Sprintf("authentication failed: %v", string(apiErr.Body()))
			return "", diagnostic
		}
		diagnostic[0].Summary = fmt.Sprintf("authentication failed: %v", err)
		return "", diagnostic
	}
	token := authOut.GetToken()

	return providerMeta{client, &token}, nil
}

func getAuthInfo(d *schema.ResourceData) (*akeyless.Auth, error) {
	login, authType, err := getLoginWithValidation(d)
	if err != nil {
		return nil, err
	}

	authBody := akeyless.NewAuthWithDefaults()
	err = setAuthBody(authBody, login, authType)
	if err != nil {
		return nil, err
	}

	return authBody, nil
}

func setAuthBody(authBody *akeyless.Auth, loginObj interface{}, authType loginType) error {

	login, ok := loginObj.(map[string]interface{})
	if !ok {
		return fmt.Errorf("wrong login detais")
	}

	switch authType {
	case ApiKeyLogin:
		accessID := login["access_id"].(string)
		accessKey := login["access_key"].(string)
		authBody.AccessId = akeyless.PtrString(accessID)
		authBody.AccessKey = akeyless.PtrString(accessKey)
		authBody.AccessType = akeyless.PtrString(common.ApiKey)
		return nil
	case EmailLogin:
		adminEmail := login["admin_email"].(string)
		adminPassword := login["admin_password"].(string)
		authBody.AdminEmail = akeyless.PtrString(adminEmail)
		authBody.AdminPassword = akeyless.PtrString(adminPassword)
		authBody.AccessType = akeyless.PtrString(common.Password)
		return nil
	case AwsIAMLogin:
		accessID := login["access_id"].(string)
		authBody.AccessId = akeyless.PtrString(accessID)
		cloudId, err := aws.GetCloudId()
		if err != nil {
			return fmt.Errorf("require Cloud ID: %v", err.Error())
		}
		authBody.CloudId = akeyless.PtrString(cloudId)
		authBody.AccessType = akeyless.PtrString(common.AwsIAM)
		return nil
	case AzureADLogin:
		accessID := login["access_id"].(string)
		authBody.AccessId = akeyless.PtrString(accessID)
		cloudId, err := azure.GetCloudId("")
		if err != nil {
			return fmt.Errorf("require Cloud ID: %v", err.Error())
		}
		authBody.CloudId = akeyless.PtrString(cloudId)
		authBody.AccessType = akeyless.PtrString(common.AzureAD)
		return nil
	case JwtLogin:
		accessID := login["access_id"].(string)
		jwt := login["jwt"].(string)
		authBody.AccessId = akeyless.PtrString(accessID)
		authBody.Jwt = akeyless.PtrString(jwt)
		authBody.AccessType = akeyless.PtrString(common.Jwt)
		return nil
	case UidLogin:
		accessID := login["access_id"].(string)
		uidToken := login["uid_token"].(string)
		authBody.AccessId = akeyless.PtrString(accessID)
		authBody.UidToken = akeyless.PtrString(uidToken)
		authBody.AccessType = akeyless.PtrString(common.Uid)
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
		authBody.AccessId = akeyless.PtrString(accessID)
		authBody.CertData = akeyless.PtrString(certData)
		authBody.KeyData = akeyless.PtrString(keyData)
		authBody.AccessType = akeyless.PtrString(common.Cert)
		return nil
	default:
		return fmt.Errorf("please choose supported login method: api_key_login/password_login/aws_iam_login/azure_ad_login/jwt_login/uid_login/cert_login")
	}
}

type providerMeta struct {
	client *akeyless.V2ApiService
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

	return nil, "", fmt.Errorf("please choose supported login method: api_key_login/password_login/aws_iam_login/azure_ad_login/jwt_login/uid_login/cert_login")
}
