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

var _ ephemeral.EphemeralResource = &pkiCertificateEphemeral{}
var _ ephemeral.EphemeralResourceWithConfigure = &pkiCertificateEphemeral{}

type pkiCertificateEphemeral struct {
	client *akeyless.ApiClient
}

func NewPKICertificate() ephemeral.EphemeralResource { return &pkiCertificateEphemeral{} }

func (r *pkiCertificateEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_certificate"
}

func (r *pkiCertificateEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generates a PKI certificate without storing it in Terraform state.",
		Attributes: map[string]schema.Attribute{
			"cert_issuer_name":   schema.StringAttribute{Required: true, Description: "The name of the PKI certificate issuer"},
			"key_data_base64":    schema.StringAttribute{Optional: true, Sensitive: true, Description: "pki key file contents encoded using Base64"},
			"csr_data_base64":    schema.StringAttribute{Optional: true, Description: "CSR contents encoded in base64"},
			"common_name":        schema.StringAttribute{Optional: true, Description: "The common name to be included in the PKI certificate"},
			"alt_names":          schema.StringAttribute{Optional: true, Description: "Subject Alternative Names (comma-delimited)"},
			"uri_sans":           schema.StringAttribute{Optional: true, Description: "URI SANs (comma-delimited)"},
			"ttl":                schema.Int64Attribute{Optional: true, Description: "Certificate lifetime in seconds"},
			"extended_key_usage": schema.StringAttribute{Optional: true, Description: "Comma-separated extended key usage requests"},
			"data":               schema.StringAttribute{Computed: true, Sensitive: true, Description: "The certificate data"},
			"parent_cert":        schema.StringAttribute{Computed: true, Description: "The parent certificate"},
			"reading_token":      schema.StringAttribute{Computed: true, Sensitive: true, Description: "The reading token"},
			"cert_display_id":    schema.StringAttribute{Computed: true, Description: "The certificate display ID"},
			"cert_item_id":       schema.Int64Attribute{Computed: true, Description: "The certificate item ID"},
			"path":               schema.StringAttribute{Computed: true, Description: "The path of the certificate"},
		},
	}
}

func (r *pkiCertificateEphemeral) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	r.client = clientFrom(req, &resp.Diagnostics)
}

type pkiCertificateModel struct {
	CertIssuerName   types.String `tfsdk:"cert_issuer_name"`
	KeyDataBase64    types.String `tfsdk:"key_data_base64"`
	CsrDataBase64    types.String `tfsdk:"csr_data_base64"`
	CommonName       types.String `tfsdk:"common_name"`
	AltNames         types.String `tfsdk:"alt_names"`
	UriSans          types.String `tfsdk:"uri_sans"`
	Ttl              types.Int64  `tfsdk:"ttl"`
	ExtendedKeyUsage types.String `tfsdk:"extended_key_usage"`
	Data             types.String `tfsdk:"data"`
	ParentCert       types.String `tfsdk:"parent_cert"`
	ReadingToken     types.String `tfsdk:"reading_token"`
	CertDisplayId    types.String `tfsdk:"cert_display_id"`
	CertItemId       types.Int64  `tfsdk:"cert_item_id"`
	Path             types.String `tfsdk:"path"`
}

func (r *pkiCertificateEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var data pkiCertificateModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	token := r.client.Token
	body := akeyless_api.GetPKICertificate{CertIssuerName: data.CertIssuerName.ValueString(), Token: &token}
	if !data.KeyDataBase64.IsNull() {
		common.GetAkeylessPtr(&body.KeyDataBase64, data.KeyDataBase64.ValueString())
	}
	if !data.CsrDataBase64.IsNull() {
		common.GetAkeylessPtr(&body.CsrDataBase64, data.CsrDataBase64.ValueString())
	}
	if !data.CommonName.IsNull() {
		common.GetAkeylessPtr(&body.CommonName, data.CommonName.ValueString())
	}
	if !data.AltNames.IsNull() {
		common.GetAkeylessPtr(&body.AltNames, data.AltNames.ValueString())
	}
	if !data.UriSans.IsNull() {
		common.GetAkeylessPtr(&body.UriSans, data.UriSans.ValueString())
	}
	if !data.Ttl.IsNull() {
		common.GetAkeylessPtr(&body.Ttl, int(data.Ttl.ValueInt64()))
	}
	if !data.ExtendedKeyUsage.IsNull() {
		common.GetAkeylessPtr(&body.ExtendedKeyUsage, data.ExtendedKeyUsage.ValueString())
	}

	rOut, _, err := r.client.Client.GetPKICertificate(ctx).Body(body).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Get PKI certificate failed", err.Error())
		return
	}
	if rOut.Data != nil {
		data.Data = types.StringValue(*rOut.Data)
	}
	if rOut.ParentCert != nil {
		data.ParentCert = types.StringValue(*rOut.ParentCert)
	}
	if rOut.ReadingToken != nil {
		data.ReadingToken = types.StringValue(*rOut.ReadingToken)
	}
	if rOut.CertDisplayId != nil {
		data.CertDisplayId = types.StringValue(*rOut.CertDisplayId)
	}
	if rOut.CertItemId != nil {
		data.CertItemId = types.Int64Value(int64(*rOut.CertItemId))
	}
	if rOut.Path != nil {
		data.Path = types.StringValue(*rOut.Path)
	}
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
