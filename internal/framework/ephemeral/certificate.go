package ephemeral

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ephemeral.EphemeralResource = &certificateEphemeral{}
var _ ephemeral.EphemeralResourceWithConfigure = &certificateEphemeral{}

type certificateEphemeral struct {
	client *akeyless.ApiClient
}

func NewCertificate() ephemeral.EphemeralResource { return &certificateEphemeral{} }

func (r *certificateEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *certificateEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches a certificate value without storing it in Terraform state.",
		Attributes: map[string]schema.Attribute{
			"name":            schema.StringAttribute{Optional: true, Description: "Certificate name"},
			"version":         schema.Int64Attribute{Optional: true, Description: "Certificate version"},
			"ignore_cache":    schema.StringAttribute{Optional: true, Description: "Retrieve without checking Gateway cache [true/false]"},
			"certificate_pem": schema.StringAttribute{Computed: true, Sensitive: true, Description: "The certificate value in pem format"},
			"private_key_pem": schema.StringAttribute{Computed: true, Sensitive: true, Description: "The private key value in pem format"},
		},
	}
}

func (r *certificateEphemeral) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	r.client = clientFrom(req, &resp.Diagnostics)
}

type certificateModel struct {
	Name           types.String `tfsdk:"name"`
	Version        types.Int64  `tfsdk:"version"`
	IgnoreCache    types.String `tfsdk:"ignore_cache"`
	CertificatePem types.String `tfsdk:"certificate_pem"`
	PrivateKeyPem  types.String `tfsdk:"private_key_pem"`
}

func (r *certificateEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var data certificateModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	token := r.client.Token
	body := akeyless_api.GetCertificateValue{Token: &token}
	if !data.Name.IsNull() {
		common.GetAkeylessPtr(&body.Name, data.Name.ValueString())
	}
	if !data.Version.IsNull() {
		common.GetAkeylessPtr(&body.Version, int(data.Version.ValueInt64()))
	}
	ignoreCache := "false"
	if !data.IgnoreCache.IsNull() && data.IgnoreCache.ValueString() != "" {
		ignoreCache = data.IgnoreCache.ValueString()
	}
	common.GetAkeylessPtr(&body.IgnoreCache, ignoreCache)

	rOut, _, err := r.client.Client.GetCertificateValue(ctx).Body(body).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Get certificate failed", err.Error())
		return
	}
	if rOut.CertificatePem != nil {
		data.CertificatePem = types.StringValue(*rOut.CertificatePem)
	}
	if rOut.PrivateKeyPem != nil {
		data.PrivateKeyPem = types.StringValue(*rOut.PrivateKeyPem)
	}
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
