// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayUpdateLogForwardingAzureAnalytics() *schema.Resource {
	return &schema.Resource{
		Description:   "Log Forwarding config for azure-analytics",
		Create:        resourceGatewayUpdateLogForwardingAzureAnalyticsUpdate,
		Read:          resourceGatewayUpdateLogForwardingAzureAnalyticsRead,
		Update:        resourceGatewayUpdateLogForwardingAzureAnalyticsUpdate,
		DeleteContext: resourceGatewayUpdateLogForwardingAzureAnalyticsDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateLogForwardingAzureAnalyticsImport,
		},
		Schema: map[string]*schema.Schema{
			"enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable Log Forwarding [true/false]",
				Default:     "true",
			},
			"enable_batch": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable batch forwarding [true/false]",
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
			"workspace_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure workspace id",
			},
			"workspace_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Azure workspace key",
			},
		},
	}
}

func resourceGatewayUpdateLogForwardingAzureAnalyticsRead(d *schema.ResourceData, m interface{}) error {

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

	config := rOut.AzureAnalyticsConfig
	if config != nil {
		if config.AzureEnableBatch != nil {
			err := d.Set("enable_batch", *config.AzureEnableBatch)
			if err != nil {
				return err
			}
		}
		if config.AzureWorkspaceId != nil {
			err := d.Set("workspace_id", *config.AzureWorkspaceId)
			if err != nil {
				return err
			}
		}
		if config.AzureWorkspaceKey != nil {
			err := d.Set("workspace_key", *config.AzureWorkspaceKey)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGatewayUpdateLogForwardingAzureAnalyticsUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	enable := d.Get("enable").(string)
	enableBatch := d.Get("enable_batch").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	workspaceId := d.Get("workspace_id").(string)
	workspaceKey := d.Get("workspace_key").(string)

	body := akeyless_api.GatewayUpdateLogForwardingAzureAnalytics{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.EnableBatch, enableBatch)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.WorkspaceId, workspaceId)
	common.GetAkeylessPtr(&body.WorkspaceKey, workspaceKey)

	_, resp, err := client.GatewayUpdateLogForwardingAzureAnalytics(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update log forwarding settings", resp, err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGatewayUpdateLogForwardingAzureAnalyticsDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateLogForwardingAzureAnalyticsImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

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

	config := rOut.AzureAnalyticsConfig
	if config != nil {
		if config.AzureEnableBatch != nil {
			err := d.Set("enable_batch", *config.AzureEnableBatch)
			if err != nil {
				return nil, err
			}
		}
		if config.AzureWorkspaceId != nil {
			err := d.Set("workspace_id", *config.AzureWorkspaceId)
			if err != nil {
				return nil, err
			}
		}
		if config.AzureWorkspaceKey != nil {
			err := d.Set("workspace_key", *config.AzureWorkspaceKey)
			if err != nil {
				return nil, err
			}
		}
	}

	return []*schema.ResourceData{d}, nil
}
