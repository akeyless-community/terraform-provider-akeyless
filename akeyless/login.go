package akeyless

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

type loginType string

const (
	ApiKeyLogin  loginType = "api_key_login"
	AwsIAMLogin  loginType = "aws_iam_login"
	GcpIAMLogin  loginType = "gcp_login"
	AzureADLogin loginType = "azure_ad_login"
	JwtLogin     loginType = "jwt_login"
	EmailLogin   loginType = "email_login"
	UidLogin     loginType = "uid_login"
	CertLogin    loginType = "cert_login"
)

var apiKeyLoginSchema = &schema.Schema{
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
}

var awsIamLoginSchema = &schema.Schema{
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
}

var gcpLoginSchema = &schema.Schema{
	Type:        schema.TypeList,
	Optional:    true,
	Description: "A configuration block, described below, that attempts to authenticate using GCP-IAM authentication credentials.",
	Elem: &schema.Resource{
		Schema: map[string]*schema.Schema{
			"access_id": {
				Type:     schema.TypeString,
				Required: true,
			},
			"audience": {
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	},
}

var azureAdLoginSchema = &schema.Schema{
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
}

var jwtLoginSchema = &schema.Schema{
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
}

var emailLoginSchema = &schema.Schema{
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
}

var uidLoginSchema = &schema.Schema{
	Type:        schema.TypeList,
	Optional:    true,
	Description: "A configuration block, described below, that attempts to authenticate using Universal Identity authentication.",
	Elem: &schema.Resource{
		Schema: map[string]*schema.Schema{
			"access_id": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"uid_token": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_AUTH_UID", nil),
			},
		},
	},
}

var certLoginSchema = &schema.Schema{
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
}

var tokenLoginSchema = &schema.Schema{
	Type:        schema.TypeList,
	Optional:    true,
	Description: "A configuration block, described below, that attempts to authenticate using akeyless token. The token can be provided as a command line variable or it will be pulled out of an environment variable named AKEYLESS_AUTH_TOKEN.",
	Elem: &schema.Resource{
		Schema: map[string]*schema.Schema{
			"token": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_AUTH_TOKEN", nil),
			},
		},
	},
}
