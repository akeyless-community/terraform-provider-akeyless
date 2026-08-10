package framework

import (
	"context"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	"github.com/akeylesslabs/terraform-provider-akeyless/internal/framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	fwephemeral "github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.Provider = &Provider{}
var _ provider.ProviderWithEphemeralResources = &Provider{}

// Provider is the Framework half of the muxed Akeyless provider.
// It only serves ephemeral resources; managed resources and data sources stay on SDK v2.
// Provider config schema MUST mirror akeyless.Provider() for mux equality.
type Provider struct {
	primary interface{ Meta() interface{} }
}

func New(primary interface{ Meta() interface{} }) provider.Provider {
	return &Provider{primary: primary}
}

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

func (p *Provider) Configure(_ context.Context, _ provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	meta, ok := p.primary.Meta().(interface{ ApiClient() *akeyless.ApiClient })
	if !ok {
		resp.Diagnostics.AddError("Provider not configured", "Akeyless SDK provider metadata is unavailable")
		return
	}
	client := meta.ApiClient()
	if client == nil {
		resp.Diagnostics.AddError("Provider not configured", "Akeyless SDK provider authentication is unavailable")
		return
	}
	resp.EphemeralResourceData = client
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
