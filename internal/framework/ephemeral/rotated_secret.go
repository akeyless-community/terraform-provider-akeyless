package ephemeral

import (
	"context"
	"encoding/json"
	"errors"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ephemeral.EphemeralResource = &rotatedSecretEphemeral{}
var _ ephemeral.EphemeralResourceWithConfigure = &rotatedSecretEphemeral{}

type rotatedSecretEphemeral struct {
	client *akeyless.ApiClient
}

func NewRotatedSecret() ephemeral.EphemeralResource { return &rotatedSecretEphemeral{} }

func (r *rotatedSecretEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rotated_secret"
}

func (r *rotatedSecretEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches a rotated secret value without storing it in Terraform state.",
		Attributes: map[string]schema.Attribute{
			"name":         schema.StringAttribute{Required: true, Description: "Secret name"},
			"version":      schema.Int64Attribute{Optional: true, Description: "Secret version"},
			"host":         schema.StringAttribute{Optional: true, Description: "Host (Linked Target only)"},
			"ignore_cache": schema.StringAttribute{Optional: true, Description: "Retrieve without checking Gateway cache [true/false]"},
			"value":        schema.StringAttribute{Computed: true, Sensitive: true, Description: "output"},
		},
	}
}

func (r *rotatedSecretEphemeral) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	r.client = clientFrom(req, &resp.Diagnostics)
}

type rotatedSecretModel struct {
	Name        types.String `tfsdk:"name"`
	Version     types.Int64  `tfsdk:"version"`
	Host        types.String `tfsdk:"host"`
	IgnoreCache types.String `tfsdk:"ignore_cache"`
	Value       types.String `tfsdk:"value"`
}

func (r *rotatedSecretEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var data rotatedSecretModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	token := r.client.Token
	body := akeyless_api.GetRotatedSecretValue{Names: data.Name.ValueString(), Token: &token}
	if !data.Version.IsNull() {
		common.GetAkeylessPtr(&body.Version, int(data.Version.ValueInt64()))
	}
	if !data.Host.IsNull() {
		common.GetAkeylessPtr(&body.Host, data.Host.ValueString())
	}
	ignoreCache := "false"
	if !data.IgnoreCache.IsNull() && data.IgnoreCache.ValueString() != "" {
		ignoreCache = data.IgnoreCache.ValueString()
	}
	common.GetAkeylessPtr(&body.IgnoreCache, ignoreCache)

	rOut, _, err := r.client.Client.GetRotatedSecretValue(ctx).Body(body).Execute()
	if err != nil {
		var apiErr akeyless_api.GenericOpenAPIError
		if !errors.As(err, &apiErr) || json.Unmarshal(apiErr.Body(), &rOut) != nil {
			resp.Diagnostics.AddError("Get rotated secret failed", err.Error())
			return
		}
	}
	b, err := json.Marshal(rOut)
	if err != nil {
		resp.Diagnostics.AddError("Marshal rotated secret failed", err.Error())
		return
	}
	data.Value = types.StringValue(string(b))
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
