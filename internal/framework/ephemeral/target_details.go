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

var _ ephemeral.EphemeralResource = &targetDetailsEphemeral{}
var _ ephemeral.EphemeralResourceWithConfigure = &targetDetailsEphemeral{}

type targetDetailsEphemeral struct {
	client *akeyless.ApiClient
}

func NewTargetDetails() ephemeral.EphemeralResource { return &targetDetailsEphemeral{} }

func (r *targetDetailsEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_target_details"
}

func (r *targetDetailsEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches target details (including credentials) without storing them in Terraform state.",
		Attributes: map[string]schema.Attribute{
			"name":           schema.StringAttribute{Required: true, Description: "Target name"},
			"target_version": schema.Int64Attribute{Optional: true, Description: "Target version"},
			"show_versions":  schema.BoolAttribute{Optional: true, Description: "Include all target versions in reply"},
			"value": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Sensitive:   true,
				Description: "Target credentials/details map (same shape as the data source).",
			},
		},
	}
}

func (r *targetDetailsEphemeral) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	r.client = clientFrom(req, &resp.Diagnostics)
}

type targetDetailsModel struct {
	Name          types.String `tfsdk:"name"`
	TargetVersion types.Int64  `tfsdk:"target_version"`
	ShowVersions  types.Bool   `tfsdk:"show_versions"`
	Value         types.Map    `tfsdk:"value"`
}

func (r *targetDetailsEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var data targetDetailsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	token := r.client.Token
	body := akeyless_api.TargetGetDetails{
		Name:  data.Name.ValueString(),
		Token: &token,
	}
	if !data.TargetVersion.IsNull() {
		common.GetAkeylessPtr(&body.TargetVersion, int(data.TargetVersion.ValueInt64()))
	}
	showVersions := false
	if !data.ShowVersions.IsNull() {
		showVersions = data.ShowVersions.ValueBool()
	}
	common.GetAkeylessPtr(&body.ShowVersions, showVersions)

	rOut, res, err := r.client.Client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Get target details failed", fmt.Sprintf("%v (status=%v)", err, res))
		return
	}
	if rOut.Value == nil {
		resp.Diagnostics.AddError("Get target details failed", "empty details")
		return
	}

	value, err := akeyless.ExtractTargetDetailsValue(rOut.Value, rOut.Target)
	if err != nil {
		resp.Diagnostics.AddError("Get target details failed", err.Error())
		return
	}
	m, diags := types.MapValueFrom(ctx, types.StringType, value)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Value = m
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
