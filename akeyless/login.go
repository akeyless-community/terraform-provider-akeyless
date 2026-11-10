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
	Description: "A configuration block, described below, that attempts to authenticate using API-Key. The access ID and key can be pulled out of the environment variables AKEYLESS_ACCESS_ID and AKEYLESS_ACCESS_KEY.",
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
	Description: "A configuration block, described below, that attempts to authenticate using AWS-IAM authentication credentials. The access ID can be pulled out of the environment variable AKEYLESS_ACCESS_ID.",
	Elem: &schema.Resource{
		Schema: map[string]*schema.Schema{
			"access_id": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_ACCESS_ID", nil),
			},
		},
	},
}

var gcpLoginSchema = &schema.Schema{
	Type:        schema.TypeList,
	Optional:    true,
	Description: "A configuration block, described below, that attempts to authenticate using GCP-IAM authentication credentials. The access ID and audience can be pulled out of the environment variables AKEYLESS_ACCESS_ID and AKEYLESS_GCP_AUDIENCE.",
	Elem: &schema.Resource{
		Schema: map[string]*schema.Schema{
			"access_id": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_ACCESS_ID", nil),
			},
			"audience": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_GCP_AUDIENCE", nil),
			},
		},
	},
}

var azureAdLoginSchema = &schema.Schema{
	Type:        schema.TypeList,
	Optional:    true,
	Description: "A configuration block, described below, that attempts to authenticate using Azure Active Directory authentication. The access ID can be pulled out of the environment variable AKEYLESS_ACCESS_ID.",
	Elem: &schema.Resource{
		Schema: map[string]*schema.Schema{
			"access_id": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_ACCESS_ID", nil),
			},
		},
	},
}

var jwtLoginSchema = &schema.Schema{
	Type:        schema.TypeList,
	Optional:    true,
	Description: "A configuration block, described below, that attempts to authenticate using JWT authentication.  The access ID and JWT can be provided as arguments or pulled out of the environment variables AKEYLESS_ACCESS_ID and AKEYLESS_AUTH_JWT (or a file named by AKEYLESS_AUTH_JWT_FILE).",
	Elem: &schema.Resource{
		Schema: map[string]*schema.Schema{
			"access_id": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_ACCESS_ID", nil),
			},
			"jwt": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				DefaultFunc: jwtDefaultFunc,
			},
		},
	},
}

var emailLoginSchema = &schema.Schema{
	Type:        schema.TypeList,
	Optional:    true,
	Description: "A configuration block, described below, that attempts to authenticate using email and password. The email and password can be pulled out of the environment variables AKEYLESS_EMAIL and AKEYLESS_PASSWORD.",
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
	Description: "A configuration block, described below, that attempts to authenticate using Universal Identity authentication. The access ID and token can be pulled out of the environment variables AKEYLESS_ACCESS_ID and AKEYLESS_AUTH_UID.",
	Elem: &schema.Resource{
		Schema: map[string]*schema.Schema{
			"access_id": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_ACCESS_ID", nil),
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
	Description: "A configuration block, described below, that attempts to authenticate using Certificate authentication.  The access ID, Certificate and Private key can be provided as arguments or pulled out of the environment variables AKEYLESS_ACCESS_ID, AKEYLESS_AUTH_CERT and AKEYLESS_AUTH_KEY.",
	Elem: &schema.Resource{
		Schema: map[string]*schema.Schema{
			"access_id": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("AKEYLESS_ACCESS_ID", nil),
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
