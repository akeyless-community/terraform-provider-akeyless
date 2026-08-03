package akeyless

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

// LoginType identifies which provider login block was used.
type LoginType string

const (
	ApiKeyLogin  LoginType = "api_key_login"
	AwsIAMLogin  LoginType = "aws_iam_login"
	GcpIAMLogin  LoginType = "gcp_login"
	AzureADLogin LoginType = "azure_ad_login"
	JwtLogin     LoginType = "jwt_login"
	EmailLogin   LoginType = "email_login"
	UidLogin     LoginType = "uid_login"
	CertLogin    LoginType = "cert_login"
)

// loginType is kept as an alias so existing unexported helpers keep compiling.
type loginType = LoginType

// Note: access_id/access_key are Optional (not Required) with no DefaultFunc,
// even though at least one of them is effectively mandatory. This is required
// so this schema can be mirrored exactly by a terraform-plugin-framework
// provider when muxed together (ephemeral resources). The env var fallback
// and "must be set" validation are applied explicitly in setAuthBody instead
// of via schema DefaultFunc, since Framework has no DefaultFunc equivalent
// for provider-level schemas.
var apiKeyLoginSchema = &schema.Schema{
	Type:        schema.TypeList,
	Optional:    true,
	Description: "A configuration block, described below, that attempts to authenticate using API-Key.",
	Elem: &schema.Resource{
		Schema: map[string]*schema.Schema{
			"access_id": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"access_key": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
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
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
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
				Type:     schema.TypeString,
				Optional: true,
			},
			"admin_password": {
				Type:     schema.TypeString,
				Optional: true,
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
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
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
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
			},
			"key_file_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"key_data": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
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
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
			},
		},
	},
}
