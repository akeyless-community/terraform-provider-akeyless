package framework

import (
	"context"
	"fmt"
	"os"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	"github.com/akeylesslabs/terraform-provider-akeyless/internal/framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	fwephemeral "github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = &Provider{}
var _ provider.ProviderWithEphemeralResources = &Provider{}

// Provider is the Framework half of the muxed Akeyless provider.
// It only serves ephemeral resources; managed resources and data sources stay on SDK v2.
// Provider config schema MUST mirror akeyless.Provider() for mux equality.
type Provider struct{}

func New() provider.Provider { return &Provider{} }

func (p *Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "akeyless"
}

func (p *Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"api_gateway_address": schema.StringAttribute{
				Optional:    true,
				Description: "Origin URL of the API Gateway server. This is a URL with a scheme, a hostname and a port.",
			},
		},
		Blocks: map[string]schema.Block{
			"api_key_login": schema.ListNestedBlock{
				Description: "A configuration block, described below, that attempts to authenticate using API-Key.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"access_id":  schema.StringAttribute{Optional: true},
						"access_key": schema.StringAttribute{Optional: true, Sensitive: true},
					},
				},
			},
			"aws_iam_login": schema.ListNestedBlock{
				Description: "A configuration block, described below, that attempts to authenticate using AWS-IAM authentication credentials.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"access_id": schema.StringAttribute{Required: true},
					},
				},
			},
			"gcp_login": schema.ListNestedBlock{
				Description: "A configuration block, described below, that attempts to authenticate using GCP-IAM authentication credentials.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"access_id": schema.StringAttribute{Required: true},
						"audience":  schema.StringAttribute{Optional: true},
					},
				},
			},
			"azure_ad_login": schema.ListNestedBlock{
				Description: "A configuration block, described below, that attempts to authenticate using Azure Active Directory authentication.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"access_id": schema.StringAttribute{Required: true},
					},
				},
			},
			"jwt_login": schema.ListNestedBlock{
				Description: "A configuration block, described below, that attempts to authenticate using JWT authentication.  The JWT can be provided as a command line variable or it will be pulled out of an environment variable named AKEYLESS_AUTH_JWT.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"access_id": schema.StringAttribute{Required: true},
						"jwt":       schema.StringAttribute{Optional: true, Sensitive: true},
					},
				},
			},
			"email_login": schema.ListNestedBlock{
				Description: "A configuration block, described below, that attempts to authenticate using email and password.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"admin_email":    schema.StringAttribute{Optional: true},
						"admin_password": schema.StringAttribute{Optional: true},
					},
				},
			},
			"uid_login": schema.ListNestedBlock{
				Description: "A configuration block, described below, that attempts to authenticate using Universal Identity authentication.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"access_id": schema.StringAttribute{Optional: true},
						"uid_token": schema.StringAttribute{Optional: true, Sensitive: true},
					},
				},
			},
			"cert_login": schema.ListNestedBlock{
				Description: "A configuration block, described below, that attempts to authenticate using Certificate authentication.  The Certificate and the Private key can be provided as a command line variable or it will be pulled out of an environment variable named AKEYLESS_AUTH_CERT and AKEYLESS_AUTH_KEY.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"access_id":      schema.StringAttribute{Required: true},
						"cert_file_name": schema.StringAttribute{Optional: true},
						"cert_data":      schema.StringAttribute{Optional: true, Sensitive: true},
						"key_file_name":  schema.StringAttribute{Optional: true},
						"key_data":       schema.StringAttribute{Optional: true, Sensitive: true},
					},
				},
			},
			"token_login": schema.ListNestedBlock{
				Description: "A configuration block, described below, that attempts to authenticate using akeyless token. The token can be provided as a command line variable or it will be pulled out of an environment variable named AKEYLESS_AUTH_TOKEN.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"token": schema.StringAttribute{Optional: true, Sensitive: true},
					},
				},
			},
		},
	}
}

type providerModel struct {
	APIGatewayAddress types.String       `tfsdk:"api_gateway_address"`
	APIKeyLogin       []apiKeyLoginModel `tfsdk:"api_key_login"`
	AwsIamLogin       []accessIDModel    `tfsdk:"aws_iam_login"`
	GcpLogin          []gcpLoginModel    `tfsdk:"gcp_login"`
	AzureAdLogin      []accessIDModel    `tfsdk:"azure_ad_login"`
	JwtLogin          []jwtLoginModel    `tfsdk:"jwt_login"`
	EmailLogin        []emailLoginModel  `tfsdk:"email_login"`
	UidLogin          []uidLoginModel    `tfsdk:"uid_login"`
	CertLogin         []certLoginModel   `tfsdk:"cert_login"`
	TokenLogin        []tokenLoginModel  `tfsdk:"token_login"`
}

type apiKeyLoginModel struct {
	AccessID  types.String `tfsdk:"access_id"`
	AccessKey types.String `tfsdk:"access_key"`
}

type accessIDModel struct {
	AccessID types.String `tfsdk:"access_id"`
}

type gcpLoginModel struct {
	AccessID types.String `tfsdk:"access_id"`
	Audience types.String `tfsdk:"audience"`
}

type jwtLoginModel struct {
	AccessID types.String `tfsdk:"access_id"`
	JWT      types.String `tfsdk:"jwt"`
}

type emailLoginModel struct {
	AdminEmail    types.String `tfsdk:"admin_email"`
	AdminPassword types.String `tfsdk:"admin_password"`
}

type uidLoginModel struct {
	AccessID types.String `tfsdk:"access_id"`
	UIDToken types.String `tfsdk:"uid_token"`
}

type certLoginModel struct {
	AccessID     types.String `tfsdk:"access_id"`
	CertFileName types.String `tfsdk:"cert_file_name"`
	CertData     types.String `tfsdk:"cert_data"`
	KeyFileName  types.String `tfsdk:"key_file_name"`
	KeyData      types.String `tfsdk:"key_data"`
}

type tokenLoginModel struct {
	Token types.String `tfsdk:"token"`
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	client, err := authenticate(ctx, cfg)
	if err != nil {
		resp.Diagnostics.AddWarning("Akeyless authentication failed", err.Error())
		return
	}

	resp.EphemeralResourceData = client
}

func authenticate(ctx context.Context, cfg providerModel) (*akeyless.ApiClient, error) {
	gw := ""
	if !cfg.APIGatewayAddress.IsNull() {
		gw = cfg.APIGatewayAddress.ValueString()
	}

	if len(cfg.TokenLogin) > 1 {
		return nil, fmt.Errorf("token_login block may appear only once")
	}
	if len(cfg.TokenLogin) == 1 {
		return akeyless.NewApiClientWithToken(gw, strVal(cfg.TokenLogin[0].Token))
	}

	if len(cfg.APIKeyLogin) > 1 {
		return nil, fmt.Errorf("api_key_login block may appear only once")
	}
	if len(cfg.APIKeyLogin) == 1 {
		return akeyless.NewApiClient(ctx, gw, string(akeyless.ApiKeyLogin), map[string]interface{}{
			"access_id":  strVal(cfg.APIKeyLogin[0].AccessID),
			"access_key": strVal(cfg.APIKeyLogin[0].AccessKey),
		})
	}
	if len(cfg.EmailLogin) > 1 {
		return nil, fmt.Errorf("email_login block may appear only once")
	}
	if len(cfg.EmailLogin) == 1 {
		return akeyless.NewApiClient(ctx, gw, string(akeyless.EmailLogin), map[string]interface{}{
			"admin_email":    strVal(cfg.EmailLogin[0].AdminEmail),
			"admin_password": strVal(cfg.EmailLogin[0].AdminPassword),
		})
	}
	if len(cfg.AwsIamLogin) > 1 {
		return nil, fmt.Errorf("aws_iam_login block may appear only once")
	}
	if len(cfg.AwsIamLogin) == 1 {
		return akeyless.NewApiClient(ctx, gw, string(akeyless.AwsIAMLogin), map[string]interface{}{
			"access_id": strVal(cfg.AwsIamLogin[0].AccessID),
		})
	}
	if len(cfg.GcpLogin) > 1 {
		return nil, fmt.Errorf("gcp_login block may appear only once")
	}
	if len(cfg.GcpLogin) == 1 {
		return akeyless.NewApiClient(ctx, gw, string(akeyless.GcpIAMLogin), map[string]interface{}{
			"access_id": strVal(cfg.GcpLogin[0].AccessID),
			"audience":  strVal(cfg.GcpLogin[0].Audience),
		})
	}
	if len(cfg.AzureAdLogin) > 1 {
		return nil, fmt.Errorf("azure_ad_login block may appear only once")
	}
	if len(cfg.AzureAdLogin) == 1 {
		return akeyless.NewApiClient(ctx, gw, string(akeyless.AzureADLogin), map[string]interface{}{
			"access_id": strVal(cfg.AzureAdLogin[0].AccessID),
		})
	}
	if len(cfg.JwtLogin) > 1 {
		return nil, fmt.Errorf("jwt_login block may appear only once")
	}
	if len(cfg.JwtLogin) == 1 {
		return akeyless.NewApiClient(ctx, gw, string(akeyless.JwtLogin), map[string]interface{}{
			"access_id": strVal(cfg.JwtLogin[0].AccessID),
			"jwt":       strVal(cfg.JwtLogin[0].JWT),
		})
	}
	if len(cfg.UidLogin) > 1 {
		return nil, fmt.Errorf("uid_login block may appear only once")
	}
	if len(cfg.UidLogin) == 1 {
		return akeyless.NewApiClient(ctx, gw, string(akeyless.UidLogin), map[string]interface{}{
			"access_id": strVal(cfg.UidLogin[0].AccessID),
			"uid_token": strVal(cfg.UidLogin[0].UIDToken),
		})
	}
	if len(cfg.CertLogin) > 1 {
		return nil, fmt.Errorf("cert_login block may appear only once")
	}
	if len(cfg.CertLogin) == 1 {
		return akeyless.NewApiClient(ctx, gw, string(akeyless.CertLogin), map[string]interface{}{
			"access_id":      strVal(cfg.CertLogin[0].AccessID),
			"cert_file_name": strVal(cfg.CertLogin[0].CertFileName),
			"cert_data":      strVal(cfg.CertLogin[0].CertData),
			"key_file_name":  strVal(cfg.CertLogin[0].KeyFileName),
			"key_data":       strVal(cfg.CertLogin[0].KeyData),
		})
	}

	if os.Getenv("AKEYLESS_ACCESS_ID") != "" && os.Getenv("AKEYLESS_ACCESS_KEY") != "" {
		return akeyless.NewApiClient(ctx, gw, string(akeyless.ApiKeyLogin), map[string]interface{}{
			"access_id":  "",
			"access_key": "",
		})
	}

	return nil, fmt.Errorf("please choose supported login method: api_key_login/password_login/aws_iam_login/gcp_login/azure_ad_login/jwt_login/uid_login/cert_login/token_login")
}

func strVal(v types.String) string {
	if v.IsNull() {
		return ""
	}
	return v.ValueString()
}

func (p *Provider) Resources(_ context.Context) []func() resource.Resource { return nil }

func (p *Provider) DataSources(_ context.Context) []func() datasource.DataSource { return nil }

func (p *Provider) EphemeralResources(_ context.Context) []func() fwephemeral.EphemeralResource {
	return []func() fwephemeral.EphemeralResource{
		ephemeral.NewDynamicSecret,
		ephemeral.NewStaticSecret,
		ephemeral.NewRotatedSecret,
		ephemeral.NewCertificate,
		ephemeral.NewPKICertificate,
		ephemeral.NewSSHCertificate,
		ephemeral.NewTargetDetails,
	}
}
