// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceGatewayUpdateLogForwardingSumologic() *schema.Resource {
	return &schema.Resource{
		Description:   "Log Forwarding config for sumologic",
		Create:        resourceGatewayUpdateLogForwardingSumologicUpdate,
		Read:          resourceGatewayUpdateLogForwardingSumologicRead,
		Update:        resourceGatewayUpdateLogForwardingSumologicUpdate,
		DeleteContext: resourceGatewayUpdateLogForwardingSumologicDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateLogForwardingSumologicImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("endpoint"), cty.GetAttrPath("endpoint_wo")),
		},
		Schema: map[string]*schema.Schema{
			"enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable Log Forwarding [true/false]",
				Default:     "true",
			},
			"output_format": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Logs format [text/json]",
				Default:     "text",
			},
			"pull_interval": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Pull interval in seconds",
				Default:     "10",
			},
			"endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Sumologic endpoint URL",
			},
			"endpoint_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "Sumologic endpoint URL (write-only, not stored in state). Requires Terraform 1.11+. Bump endpoint_wo_version to change it.",
			},
			"endpoint_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for endpoint_wo. Increment to update the value.",
			},
			"sumologic_tags": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma-separated list of Sumologic tags",
				Default:     "use-existing",
			},
			"host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Sumologic host",
				Default:     "use-existing",
			},
		},
	}
}

func resourceGatewayUpdateLogForwardingSumologicRead(d *schema.ResourceData, m interface{}) error {

	rOut, err := getGwLogForwardingConfig(m)
	if err != nil {
		return err
	}

	if rOut.LoganEnable != nil {
		err := d.Set("enable", strconv.FormatBool(*rOut.LoganEnable))
		if err != nil {
			return err
		}
	}
	if rOut.JsonOutput != nil {
		err := d.Set("output_format", common.ExtractLogForwardingFormat(*rOut.JsonOutput))
		if err != nil {
			return err
		}
	}
	if rOut.PullIntervalSec != nil {
		err := d.Set("pull_interval", *rOut.PullIntervalSec)
		if err != nil {
			return err
		}
	}

	config := rOut.SumoLogicConfig
	if config != nil {
		if config.SumoLogicEndpoint != nil {
			err := common.SetSecretFromRead(d, "endpoint", "endpoint_wo", "endpoint_wo_version", *config.SumoLogicEndpoint)
			if err != nil {
				return err
			}
		}
		if config.SumoLogicTags != nil {
			err := d.Set("sumologic_tags", *config.SumoLogicTags)
			if err != nil {
				return err
			}
		}
		if config.SumoLogicHost != nil {
			err := d.Set("host", *config.SumoLogicHost)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGatewayUpdateLogForwardingSumologicUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	endpoint, err := common.EffectiveSecretValue(d, "endpoint", "endpoint_wo")
	if err != nil {
		return err
	}
	sumologicTags := d.Get("sumologic_tags").(string)
	host := d.Get("host").(string)

	body := akeyless_api.GatewayUpdateLogForwardingSumologic{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.Endpoint, endpoint)
	common.GetAkeylessPtr(&body.SumologicTags, sumologicTags)
	common.GetAkeylessPtr(&body.Host, host)

	_, resp, err := client.GatewayUpdateLogForwardingSumologic(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update log forwarding settings", resp, err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGatewayUpdateLogForwardingSumologicDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateLogForwardingSumologicImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	rOut, err := getGwLogForwardingConfig(m)
	if err != nil {
		return nil, err
	}

	if rOut.LoganEnable != nil {
		err := d.Set("enable", strconv.FormatBool(*rOut.LoganEnable))
		if err != nil {
			return nil, err
		}
	}
	if rOut.JsonOutput != nil {
		err := d.Set("output_format", common.ExtractLogForwardingFormat(*rOut.JsonOutput))
		if err != nil {
			return nil, err
		}
	}
	if rOut.PullIntervalSec != nil {
		err := d.Set("pull_interval", *rOut.PullIntervalSec)
		if err != nil {
			return nil, err
		}
	}

	config := rOut.SumoLogicConfig
	if config != nil {
		if config.SumoLogicEndpoint != nil {
			err := common.SetSecretFromRead(d, "endpoint", "endpoint_wo", "endpoint_wo_version", *config.SumoLogicEndpoint)
			if err != nil {
				return nil, err
			}
		}
		if config.SumoLogicTags != nil {
			err := d.Set("sumologic_tags", *config.SumoLogicTags)
			if err != nil {
				return nil, err
			}
		}
		if config.SumoLogicHost != nil {
			err := d.Set("host", *config.SumoLogicHost)
			if err != nil {
				return nil, err
			}
		}
	}

	return []*schema.ResourceData{d}, nil
}
