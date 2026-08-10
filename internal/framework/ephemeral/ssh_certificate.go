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

var _ ephemeral.EphemeralResource = &sshCertificateEphemeral{}
var _ ephemeral.EphemeralResourceWithConfigure = &sshCertificateEphemeral{}

type sshCertificateEphemeral struct {
	client *akeyless.ApiClient
}

func NewSSHCertificate() ephemeral.EphemeralResource { return &sshCertificateEphemeral{} }

func (r *sshCertificateEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ssh_certificate"
}

func (r *sshCertificateEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generates an SSH certificate without storing it in Terraform state.",
		Attributes: map[string]schema.Attribute{
			"cert_issuer_name":        schema.StringAttribute{Required: true, Description: "The name of the SSH certificate issuer"},
			"cert_username":           schema.StringAttribute{Required: true, Description: "The username to sign in the SSH certificate"},
			"public_key_data":         schema.StringAttribute{Required: true, Description: "SSH public key file contents"},
			"ttl":                     schema.Int64Attribute{Optional: true, Description: "Certificate lifetime in seconds"},
			"legacy_signing_alg_name": schema.BoolAttribute{Optional: true, Description: "Output legacy signing algorithm name"},
			"data":                    schema.StringAttribute{Computed: true, Sensitive: true, Description: "The signed SSH certificate"},
			"path":                    schema.StringAttribute{Computed: true, Description: "The path of the SSH certificate"},
		},
	}
}

func (r *sshCertificateEphemeral) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	r.client = clientFrom(req, &resp.Diagnostics)
}

type sshCertificateModel struct {
	CertIssuerName       types.String `tfsdk:"cert_issuer_name"`
	CertUsername         types.String `tfsdk:"cert_username"`
	PublicKeyData        types.String `tfsdk:"public_key_data"`
	Ttl                  types.Int64  `tfsdk:"ttl"`
	LegacySigningAlgName types.Bool   `tfsdk:"legacy_signing_alg_name"`
	Data                 types.String `tfsdk:"data"`
	Path                 types.String `tfsdk:"path"`
}

func (r *sshCertificateEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var data sshCertificateModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	token := r.client.Token
	body := akeyless_api.GetSSHCertificate{
		CertUsername:   data.CertUsername.ValueString(),
		CertIssuerName: data.CertIssuerName.ValueString(),
		Token:          &token,
	}
	common.GetAkeylessPtr(&body.PublicKeyData, data.PublicKeyData.ValueString())
	if !data.Ttl.IsNull() {
		common.GetAkeylessPtr(&body.Ttl, int(data.Ttl.ValueInt64()))
	}
	if !data.LegacySigningAlgName.IsNull() {
		common.GetAkeylessPtr(&body.LegacySigningAlgName, data.LegacySigningAlgName.ValueBool())
	}

	rOut, _, err := r.client.Client.GetSSHCertificate(ctx).Body(body).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Get SSH certificate failed", err.Error())
		return
	}
	if rOut.Data != nil {
		data.Data = types.StringValue(*rOut.Data)
	}
	if rOut.Path != nil {
		data.Path = types.StringValue(*rOut.Path)
	}
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
