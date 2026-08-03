package ephemeral

import (
	"context"
	"encoding/json"
	"errors"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ephemeral.EphemeralResource = &dynamicSecretEphemeral{}
var _ ephemeral.EphemeralResourceWithConfigure = &dynamicSecretEphemeral{}

type dynamicSecretEphemeral struct {
	client *akeyless.ApiClient
}

func NewDynamicSecret() ephemeral.EphemeralResource { return &dynamicSecretEphemeral{} }

func (r *dynamicSecretEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dynamic_secret"
}

func (r *dynamicSecretEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches a dynamic secret value without storing it in Terraform state.",
		Attributes: map[string]schema.Attribute{
			"path":    schema.StringAttribute{Required: true, Description: "The path where the secret is stored."},
			"args":    schema.ListAttribute{Optional: true, ElementType: types.StringType, Description: "Optional arguments as key=value pairs or JSON strings."},
			"dbname":  schema.StringAttribute{Optional: true, Description: "Optional override DB name (MSSQL only)."},
			"host":    schema.StringAttribute{Optional: true, Description: "Host"},
			"target":  schema.StringAttribute{Optional: true, Description: "Target Name"},
			"timeout": schema.Int64Attribute{Optional: true, Description: "Timeout in seconds"},
			"value":   schema.StringAttribute{Computed: true, Sensitive: true, Description: "The secret contents."},
		},
	}
}

func (r *dynamicSecretEphemeral) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	r.client = clientFrom(req, &resp.Diagnostics)
}

type dynamicSecretModel struct {
	Path    types.String `tfsdk:"path"`
	Args    types.List   `tfsdk:"args"`
	Dbname  types.String `tfsdk:"dbname"`
	Host    types.String `tfsdk:"host"`
	Target  types.String `tfsdk:"target"`
	Timeout types.Int64  `tfsdk:"timeout"`
	Value   types.String `tfsdk:"value"`
}

func (r *dynamicSecretEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var data dynamicSecretModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	token := r.client.Token
	body := akeyless_api.GetDynamicSecretValue{Name: data.Path.ValueString(), Token: &token}
	if !data.Args.IsNull() {
		var args []string
		resp.Diagnostics.Append(data.Args.ElementsAs(ctx, &args, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		body.Args = args
	}
	if !data.Dbname.IsNull() {
		v := data.Dbname.ValueString()
		body.Dbname = &v
	}
	if !data.Host.IsNull() {
		v := data.Host.ValueString()
		body.Host = &v
	}
	if !data.Target.IsNull() {
		v := data.Target.ValueString()
		body.Target = &v
	}
	if !data.Timeout.IsNull() {
		v := data.Timeout.ValueInt64()
		body.Timeout = &v
	}

	var gsvOutIntr map[string]any
	gsvOut, _, err := r.client.Client.GetDynamicSecretValue(ctx).Body(body).Execute()
	if err != nil {
		var apiErr akeyless_api.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			if uerr := json.Unmarshal(apiErr.Body(), &gsvOutIntr); uerr != nil {
				resp.Diagnostics.AddError("Get dynamic secret failed", string(apiErr.Body()))
				return
			}
		} else {
			resp.Diagnostics.AddError("Get dynamic secret failed", err.Error())
			return
		}
	}
	if gsvOutIntr != nil {
		gsvOut = make(map[string]any)
		for k, val := range gsvOutIntr {
			if s, ok := val.(string); ok {
				gsvOut[k] = s
			} else {
				ma, mErr := json.Marshal(val)
				if mErr != nil {
					resp.Diagnostics.AddError("Marshal dynamic secret value failed", mErr.Error())
					return
				}
				gsvOut[k] = string(ma)
			}
		}
	}
	var marshal []byte
	if gsvOut != nil {
		marshal, err = json.Marshal(gsvOut)
		if err != nil {
			resp.Diagnostics.AddError("Marshal dynamic secret value failed", err.Error())
			return
		}
	}
	data.Value = types.StringValue(string(marshal))
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
