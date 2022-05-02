package akeyless

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/aws"
	"github.com/akeylesslabs/akeyless-go-cloud-id/cloudprovider/azure"
	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// default: public API Gateway
const publicApi = "https://api.akeyless.io"

var apiKeyLogin []interface{}
var emailLogin []interface{}
var awsIAMLogin []interface{}
var azureADLogin []interface{}
var jwtLogin []interface{}

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
			"akeyless_auth_method_gcp":                resourceAuthMethodGcp(),
			"akeyless_auth_method_k8s":                resourceAuthMethodK8s(),
			"akeyless_auth_method_oauth2":             resourceAuthMethodOauth2(),
			"akeyless_auth_method_oidc":               resourceAuthMethodOidc(),
			"akeyless_auth_method_saml":               resourceAuthMethodSaml(),
			"akeyless_auth_method_universal_identity": resourceAuthMethodUniversalIdentity(),
			"akeyless_role":                           resourceRole(),
			"akeyless_producer_aws":                   resourceProducerAws(),
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
			"akeyless_target_github":                  resourceGithubTarget(),
			"akeyless_target_gke":                     resourceGkeTarget(),
			"akeyless_target_gcp":                     resourceGcpTarget(),
			"akeyless_target_k8s":                     resourceK8sTarget(),
			"akeyless_target_rabbit":                  resourceRabbitmqTarget(),
			"akeyless_target_web":                     resourceWebTarget(),
			"akeyless_target_ssh":                     resourceSSHTarget(),
			"akeyless_k8s_auth_config":                resourceK8sAuthConfig(),
			"akeyless_associate_role_auth_method":     resourceAssocRoleAm(),
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
			"akeyless_tags":               dataSourceGetTags(),
			"akeyless_target_details":     dataSourceGetTargetDetails(),
			"akeyless_target":             dataSourceGetTarget(),
		},
	}
}

func configureProvider(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	apiGwAddress := d.Get("api_gateway_address").(string)

	diagnostic := diag.Diagnostics{{Severity: diag.Error, Summary: ""}}
	err := inputValidation(d)
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

	authBody := akeyless.NewAuthWithDefaults()
	err = setAuthBody(authBody)
	if err != nil {
		diagnostic[0].Summary = err.Error()
		return "", diagnostic
	}

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

func setAuthBody(authBody *akeyless.Auth) error {
	if apiKeyLogin != nil && len(apiKeyLogin) == 1 {
		login, ok := apiKeyLogin[0].(map[string]interface{})
		if ok {
			accessID := login["access_id"].(string)
			accessKey := login["access_key"].(string)
			authBody.AccessId = akeyless.PtrString(accessID)
			authBody.AccessKey = akeyless.PtrString(accessKey)
			authBody.AccessType = akeyless.PtrString(common.ApiKey)

			return nil
		}
	}

	if os.Getenv("AKEYLESS_ACCESS_ID") != "" && os.Getenv("AKEYLESS_ACCESS_KEY") != "" {
		authBody.AccessId = akeyless.PtrString(os.Getenv("AKEYLESS_ACCESS_ID"))
		authBody.AccessKey = akeyless.PtrString(os.Getenv("AKEYLESS_ACCESS_KEY"))
		authBody.AccessType = akeyless.PtrString(common.ApiKey)
		return nil
	}

	if emailLogin != nil && len(emailLogin) == 1 {
		login := emailLogin[0].(map[string]interface{})
		adminEmail := login["admin_email"].(string)
		adminPassword := login["admin_password"].(string)
		authBody.AdminEmail = akeyless.PtrString(adminEmail)
		authBody.AdminPassword = akeyless.PtrString(adminPassword)
		authBody.AccessType = akeyless.PtrString(common.Password)
	} else if awsIAMLogin != nil && len(awsIAMLogin) == 1 {
		login := awsIAMLogin[0].(map[string]interface{})
		accessID := login["access_id"].(string)
		authBody.AccessId = akeyless.PtrString(accessID)
		cloudId, err := aws.GetCloudId()
		if err != nil {
			return fmt.Errorf("require Cloud ID: %v", err.Error())
		}
		authBody.CloudId = akeyless.PtrString(cloudId)
		authBody.AccessType = akeyless.PtrString(common.AwsIAM)
	} else if azureADLogin != nil && len(azureADLogin) == 1 {
		login := azureADLogin[0].(map[string]interface{})
		accessID := login["access_id"].(string)
		authBody.AccessId = akeyless.PtrString(accessID)
		cloudId, err := azure.GetCloudId("")
		if err != nil {
			return fmt.Errorf("require Cloud ID: %v", err.Error())
		}
		authBody.CloudId = akeyless.PtrString(cloudId)
		authBody.AccessType = akeyless.PtrString(common.AzureAD)
	} else if jwtLogin != nil && len(jwtLogin) == 1 {
		login := jwtLogin[0].(map[string]interface{})
		accessID := login["access_id"].(string)
		jwt := login["jwt"].(string)
		authBody.AccessId = akeyless.PtrString(accessID)
		authBody.Jwt = akeyless.PtrString(jwt)
		authBody.AccessType = akeyless.PtrString(common.Jwt)
	} else {
		return fmt.Errorf("please support login method: api_key_login/password_login/aws_iam_login/azure_ad_login/jwt_login")
	}

	return nil
}

type providerMeta struct {
	client *akeyless.V2ApiService
	token  *string
}

func inputValidation(d *schema.ResourceData) error {
	apiKeyLogin = d.Get("api_key_login").([]interface{})
	if len(apiKeyLogin) > 1 {
		return fmt.Errorf("api_key_login block may appear only once")
	}
	emailLogin = d.Get("email_login").([]interface{})
	if len(emailLogin) > 1 {
		return fmt.Errorf("emailLogin block may appear only once")
	}
	awsIAMLogin = d.Get("aws_iam_login").([]interface{})
	if len(awsIAMLogin) > 1 {
		return fmt.Errorf("aws_iam_login block may appear only once")
	}
	azureADLogin = d.Get("azure_ad_login").([]interface{})
	if len(azureADLogin) > 1 {
		return fmt.Errorf("azure_ad_login block may appear only once")
	}
	jwtLogin = d.Get("jwt_login").([]interface{})
	if len(jwtLogin) > 1 {
		return fmt.Errorf("jwt_login block may appear only once")
	}
	return nil
}
