package ephemeral

import (
	"context"
	"encoding/json"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ephemeral.EphemeralResource = &secretEphemeral{}
var _ ephemeral.EphemeralResourceWithConfigure = &secretEphemeral{}

type secretEphemeral struct {
	client *akeyless.ApiClient
}

func NewSecret() ephemeral.EphemeralResource { return &secretEphemeral{} }

func (r *secretEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches any secret value (static/dynamic/rotated) without storing it in Terraform state.",
		Attributes: map[string]schema.Attribute{
			"path":    schema.StringAttribute{Required: true, Description: "The path where the secret is stored"},
			"value":   schema.StringAttribute{Computed: true, Sensitive: true, Description: "The secret contents"},
			"version": schema.Int64Attribute{Computed: true, Description: "The version of the secret."},
		},
	}
}

func (r *secretEphemeral) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	r.client = clientFrom(req, &resp.Diagnostics)
}

type secretModel struct {
	Path    types.String `tfsdk:"path"`
	Value   types.String `tfsdk:"value"`
	Version types.Int64  `tfsdk:"version"`
}

func (r *secretEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var data secretModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	token := r.client.Token
	path := data.Path.ValueString()
	itemOut, res, err := r.client.Client.DescribeItem(ctx).Body(akeyless_api.DescribeItem{Name: path, Token: &token}).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Describe secret failed", fmt.Sprintf("%v (status=%v)", err, res))
		return
	}
	if itemOut.ItemType == nil {
		resp.Diagnostics.AddError("Describe secret failed", "item type missing")
		return
	}

	switch *itemOut.ItemType {
	case common.StaticSecretType:
		gsvOut, _, err := r.client.Client.GetSecretValue(ctx).Body(akeyless_api.GetSecretValue{Names: []string{path}, Token: &token}).Execute()
		if err != nil {
			resp.Diagnostics.AddError("Get secret failed", err.Error())
			return
		}
		s, ok := gsvOut[path].(string)
		if !ok {
			resp.Diagnostics.AddError("Get secret failed", "unexpected value type")
			return
		}
		data.Value = types.StringValue(s)
		if itemOut.LastVersion != nil {
			data.Version = types.Int64Value(int64(*itemOut.LastVersion))
		}
	case common.DynamicSecretType:
		gsvOut, _, err := r.client.Client.GetDynamicSecretValue(ctx).Body(akeyless_api.GetDynamicSecretValue{Name: path, Token: &token}).Execute()
		if err != nil {
			resp.Diagnostics.AddError("Get dynamic secret failed", err.Error())
			return
		}
		b, err := json.Marshal(gsvOut)
		if err != nil {
			resp.Diagnostics.AddError("Marshal secret failed", err.Error())
			return
		}
		data.Value = types.StringValue(string(b))
	case common.RotatedSecretType:
		rOut, _, err := r.client.Client.GetRotatedSecretValue(ctx).Body(akeyless_api.GetRotatedSecretValue{Names: path, Token: &token}).Execute()
		if err != nil {
			resp.Diagnostics.AddError("Get rotated secret failed", err.Error())
			return
		}
		b, err := json.Marshal(rOut)
		if err != nil {
			resp.Diagnostics.AddError("Marshal secret failed", err.Error())
			return
		}
		data.Value = types.StringValue(string(b))
	default:
		resp.Diagnostics.AddError("Unsupported secret type", fmt.Sprintf("unsupported secret type %q for %s", *itemOut.ItemType, path))
		return
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
