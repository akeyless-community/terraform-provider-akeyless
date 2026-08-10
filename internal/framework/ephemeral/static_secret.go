package ephemeral

import (
	"context"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ephemeral.EphemeralResource = &staticSecretEphemeral{}
var _ ephemeral.EphemeralResourceWithConfigure = &staticSecretEphemeral{}

type staticSecretEphemeral struct {
	client *akeyless.ApiClient
}

func NewStaticSecret() ephemeral.EphemeralResource { return &staticSecretEphemeral{} }

func (r *staticSecretEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_static_secret"
}

func (r *staticSecretEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches a static secret value without storing it in Terraform state.",
		Attributes: map[string]schema.Attribute{
			"path":         schema.StringAttribute{Required: true, Description: "The path where the secret is stored."},
			"version":      schema.Int64Attribute{Optional: true, Description: "The version of the secret."},
			"ignore_cache": schema.StringAttribute{Optional: true, Description: "Retrieve the Secret value without checking the Gateway's cache [true/false]"},
			"value":        schema.StringAttribute{Computed: true, Sensitive: true, Description: "The secret contents."},
		},
	}
}

func (r *staticSecretEphemeral) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	r.client = clientFrom(req, &resp.Diagnostics)
}

type staticSecretModel struct {
	Path        types.String `tfsdk:"path"`
	Version     types.Int64  `tfsdk:"version"`
	IgnoreCache types.String `tfsdk:"ignore_cache"`
	Value       types.String `tfsdk:"value"`
}

func (r *staticSecretEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var data staticSecretModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	token := r.client.Token
	path := data.Path.ValueString()
	body := akeyless_api.GetSecretValue{Names: []string{path}, Token: &token}
	if !data.Version.IsNull() && data.Version.ValueInt64() != 0 {
		v := int32(data.Version.ValueInt64())
		body.Version = &v
	}
	ignoreCache := "false"
	if !data.IgnoreCache.IsNull() && data.IgnoreCache.ValueString() != "" {
		ignoreCache = data.IgnoreCache.ValueString()
	}
	common.GetAkeylessPtr(&body.IgnoreCache, ignoreCache)

	gsvOut, res, err := r.client.Client.GetSecretValue(ctx).Body(body).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Get static secret failed", fmt.Sprintf("%v (status=%v)", err, res))
		return
	}
	value, ok := gsvOut[path]
	if !ok {
		resp.Diagnostics.AddError("Get static secret failed", "secret value missing from response")
		return
	}
	s, ok := value.(string)
	if !ok {
		resp.Diagnostics.AddError("Get static secret failed", "unexpected secret value type")
		return
	}
	data.Value = types.StringValue(s)
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
