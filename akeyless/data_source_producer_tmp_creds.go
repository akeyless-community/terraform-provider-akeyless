package akeyless

import (
	"context"
	"encoding/json"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGatewayGetProducerTmpCreds() *schema.Resource {
	return &schema.Resource{
		Description:        "Get producer temporary credentials list data source",
		DeprecationMessage: "Use akeyless_dynamic_secret_tmp_creds instead",
		Read:               dataSourceGatewayGetDynamicSecretTmpCredsRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic Secret Name",
				ForceNew:    true,
			},
			"value": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "JSON-encoded list of temporary credentials data",
			},
		},
	}
}

func dataSourceGatewayGetDynamicSecretTmpCreds() *schema.Resource {
	return &schema.Resource{
		Description: "Get dynamic secret temporary credentials list data source",
		Read:        dataSourceGatewayGetDynamicSecretTmpCredsRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic Secret Name",
				ForceNew:    true,
			},
			"value": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON-encoded list of temporary credentials data",
			},
			"ara_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable Agentic Runtime Authority",
			},
			"enable_agentic_runtime_authority": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable Agentic Runtime Authority",
			},
			"enable_ai_quorum": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable AI Quorum",
			},
			"skip_dry_run": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Skip dry run",
			},
		},
	}
}

func dataSourceGatewayGetDynamicSecretTmpCredsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.DynamicSecretTmpCredsGet{
		Name:  name,
		Token: &token,
	}
	rawConfig := d.GetRawConfig()
	if rawConfig.IsKnown() && !rawConfig.IsNull() {
		if raw := rawConfig.GetAttr("ara_enabled"); raw.IsKnown() && !raw.IsNull() {
			common.GetAkeylessPtr(&body.AraEnabled, raw.True())
		}
		if raw := rawConfig.GetAttr("enable_agentic_runtime_authority"); raw.IsKnown() && !raw.IsNull() {
			common.GetAkeylessPtr(&body.EnableAgenticRuntimeAuthority, raw.True())
		}
		if raw := rawConfig.GetAttr("enable_ai_quorum"); raw.IsKnown() && !raw.IsNull() {
			common.GetAkeylessPtr(&body.EnableAiQuorum, raw.True())
		}
		if raw := rawConfig.GetAttr("skip_dry_run"); raw.IsKnown() && !raw.IsNull() {
			common.GetAkeylessPtr(&body.SkipDryRun, raw.True())
		}
	}

	rOut, res, err := client.DynamicSecretTmpCredsGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get value", res, err)
	}
	marshalValue, err := json.Marshal(rOut)
	if err != nil {
		return err
	}
	err = d.Set("value", string(marshalValue))
	if err != nil {
		return err
	}

	d.SetId(name)
	return nil
}
