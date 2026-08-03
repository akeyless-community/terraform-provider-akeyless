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

func resourceGatewayUpdateLogForwardingLogzIo() *schema.Resource {
	return &schema.Resource{
		Description:   "Log Forwarding config for logz-io",
		Create:        resourceGatewayUpdateLogForwardingLogzIoUpdate,
		Read:          resourceGatewayUpdateLogForwardingLogzIoRead,
		Update:        resourceGatewayUpdateLogForwardingLogzIoUpdate,
		DeleteContext: resourceGatewayUpdateLogForwardingLogzIoDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateLogForwardingLogzIoImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("logz_io_token"), cty.GetAttrPath("logz_io_token_wo")),
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
			"logz_io_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Logz-io token",
			},
			"logz_io_token_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "Logz-io token (write-only, not stored in state). Requires Terraform 1.11+. Bump logz_io_token_wo_version to change it.",
			},
			"logz_io_token_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for logz_io_token_wo. Increment to update the value.",
			},
			"protocol": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "LogzIo protocol [tcp/https]",
			},
		},
	}
}

func resourceGatewayUpdateLogForwardingLogzIoRead(d *schema.ResourceData, m interface{}) error {

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

	config := rOut.LogzIoConfig
	if config != nil {
		if config.TargetLogzIoToken != nil {
			err := common.SetSecretFromRead(d, "logz_io_token", "logz_io_token_wo", "logz_io_token_wo_version", *config.TargetLogzIoToken)
			if err != nil {
				return err
			}
		}
		if config.TargetLogzIoProtocol != nil {
			err := d.Set("protocol", *config.TargetLogzIoProtocol)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGatewayUpdateLogForwardingLogzIoUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	logzIoToken, err := common.EffectiveSecretValue(d, "logz_io_token", "logz_io_token_wo")
	if err != nil {
		return err
	}
	protocol := d.Get("protocol").(string)

	body := akeyless_api.GatewayUpdateLogForwardingLogzIo{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.LogzIoToken, logzIoToken)
	common.GetAkeylessPtr(&body.Protocol, protocol)

	_, resp, err := client.GatewayUpdateLogForwardingLogzIo(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update log forwarding settings", resp, err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGatewayUpdateLogForwardingLogzIoDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateLogForwardingLogzIoImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

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

	config := rOut.LogzIoConfig
	if config != nil {
		if config.TargetLogzIoToken != nil {
			err := common.SetSecretFromRead(d, "logz_io_token", "logz_io_token_wo", "logz_io_token_wo_version", *config.TargetLogzIoToken)
			if err != nil {
				return nil, err
			}
		}
		if config.TargetLogzIoProtocol != nil {
			err := d.Set("protocol", *config.TargetLogzIoProtocol)
			if err != nil {
				return nil, err
			}
		}
	}

	return []*schema.ResourceData{d}, nil
}
