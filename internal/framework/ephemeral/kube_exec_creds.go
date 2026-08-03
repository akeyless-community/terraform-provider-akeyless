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

var _ ephemeral.EphemeralResource = &kubeExecCredsEphemeral{}
var _ ephemeral.EphemeralResourceWithConfigure = &kubeExecCredsEphemeral{}

type kubeExecCredsEphemeral struct {
	client *akeyless.ApiClient
}

func NewKubeExecCreds() ephemeral.EphemeralResource { return &kubeExecCredsEphemeral{} }

func (r *kubeExecCredsEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kube_exec_creds"
}

func (r *kubeExecCredsEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches Kubernetes exec credentials without storing them in Terraform state.",
		Attributes: map[string]schema.Attribute{
			"cert_issuer_name":        schema.StringAttribute{Required: true, Description: "The name of the PKI certificate issuer"},
			"key_data_base64":         schema.StringAttribute{Optional: true, Sensitive: true, Description: "pki key file contents encoded using Base64"},
			"common_name":             schema.StringAttribute{Optional: true, Description: "The common name to be included in the PKI certificate"},
			"alt_names":               schema.StringAttribute{Optional: true, Description: "Subject Alternative Names (comma-delimited)"},
			"uri_sans":                schema.StringAttribute{Optional: true, Description: "URI SANs (comma-delimited)"},
			"csr_data_base64":         schema.StringAttribute{Optional: true, Description: "CSR contents encoded in base64"},
			"extended_key_usage":      schema.StringAttribute{Optional: true, Description: "Comma-separated extended key usage requests"},
			"extra_extensions":        schema.StringAttribute{Optional: true, Description: "JSON string of requested extra extensions"},
			"ttl":                     schema.StringAttribute{Optional: true, Description: "Certificate lifetime in seconds"},
			"max_path_len":            schema.Int64Attribute{Optional: true, Description: "Maximum path length for the generated certificate"},
			"kind":                    schema.StringAttribute{Computed: true, Description: "The kind of the Kubernetes exec credential"},
			"api_version":             schema.StringAttribute{Computed: true, Description: "The API version of the Kubernetes exec credential"},
			"client_certificate_data": schema.StringAttribute{Computed: true, Sensitive: true, Description: "Client certificate data"},
			"client_key_data":         schema.StringAttribute{Computed: true, Sensitive: true, Description: "Client key data"},
			"parent_certificate_data": schema.ListAttribute{Computed: true, ElementType: types.StringType, Description: "Parent certificate data"},
		},
	}
}

func (r *kubeExecCredsEphemeral) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	r.client = clientFrom(req, &resp.Diagnostics)
}

type kubeExecCredsModel struct {
	CertIssuerName        types.String `tfsdk:"cert_issuer_name"`
	KeyDataBase64         types.String `tfsdk:"key_data_base64"`
	CommonName            types.String `tfsdk:"common_name"`
	AltNames              types.String `tfsdk:"alt_names"`
	UriSans               types.String `tfsdk:"uri_sans"`
	CsrDataBase64         types.String `tfsdk:"csr_data_base64"`
	ExtendedKeyUsage      types.String `tfsdk:"extended_key_usage"`
	ExtraExtensions       types.String `tfsdk:"extra_extensions"`
	Ttl                   types.String `tfsdk:"ttl"`
	MaxPathLen            types.Int64  `tfsdk:"max_path_len"`
	Kind                  types.String `tfsdk:"kind"`
	ApiVersion            types.String `tfsdk:"api_version"`
	ClientCertificateData types.String `tfsdk:"client_certificate_data"`
	ClientKeyData         types.String `tfsdk:"client_key_data"`
	ParentCertificateData types.List   `tfsdk:"parent_certificate_data"`
}

func (r *kubeExecCredsEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var data kubeExecCredsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	token := r.client.Token
	body := akeyless_api.GetKubeExecCreds{CertIssuerName: data.CertIssuerName.ValueString(), Token: &token}
	if !data.KeyDataBase64.IsNull() {
		common.GetAkeylessPtr(&body.KeyDataBase64, data.KeyDataBase64.ValueString())
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
	if !data.CsrDataBase64.IsNull() {
		common.GetAkeylessPtr(&body.CsrDataBase64, data.CsrDataBase64.ValueString())
	}
	if !data.ExtendedKeyUsage.IsNull() {
		common.GetAkeylessPtr(&body.ExtendedKeyUsage, data.ExtendedKeyUsage.ValueString())
	}
	if !data.ExtraExtensions.IsNull() {
		common.GetAkeylessPtr(&body.ExtraExtensions, data.ExtraExtensions.ValueString())
	}
	if !data.Ttl.IsNull() {
		common.GetAkeylessPtr(&body.Ttl, data.Ttl.ValueString())
	}
	if !data.MaxPathLen.IsNull() && data.MaxPathLen.ValueInt64() != 0 {
		v := data.MaxPathLen.ValueInt64()
		body.MaxPathLen = &v
	}

	rOut, _, err := r.client.Client.GetKubeExecCreds(ctx).Body(body).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Get kube exec creds failed", err.Error())
		return
	}
	if rOut.Kind != nil {
		data.Kind = types.StringValue(*rOut.Kind)
	}
	if rOut.ApiVersion != nil {
		data.ApiVersion = types.StringValue(*rOut.ApiVersion)
	}
	data.ClientCertificateData = types.StringValue(rOut.Status.GetClientCertificateData())
	data.ClientKeyData = types.StringValue(rOut.Status.GetClientKeyData())
	parent := rOut.Status.GetParentCertificateData()
	parentList, diags := types.ListValueFrom(ctx, types.StringType, parent)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.ParentCertificateData = parentList
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
