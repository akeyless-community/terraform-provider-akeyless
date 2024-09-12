// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayUpdateLogForwardingAzureAnalytics() *schema.Resource {
	return &schema.Resource{
		Description: "Log Forwarding config for azure-analytics",
		Create:      resourceGatewayUpdateLogForwardingAzureAnalyticsUpdate,
		Read:        resourceGatewayUpdateLogForwardingAzureAnalyticsRead,
		Update:      resourceGatewayUpdateLogForwardingAzureAnalyticsUpdate,
		Delete:      resourceGatewayUpdateLogForwardingAzureAnalyticsUpdate,
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

	rOut, err := getGwLogForwardingConfig(d, m)
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
		if config.AzureWorkspaceId != nil && d.Get("workspace_id") != "" {
			err := d.Set("workspace_id", *config.AzureWorkspaceId)
			if err != nil {
				return err
			}
		}
		if config.AzureWorkspaceKey != nil && d.Get("workspace_key") != "" {
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

	ctx := context.Background()
	token, err := provider.getToken(ctx, d)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	var apiErr akeyless_api.GenericOpenAPIError

	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	workspaceId := d.Get("workspace_id").(string)
	workspaceKey := d.Get("workspace_key").(string)

	body := akeyless_api.GatewayUpdateLogForwardingAzureAnalytics{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.WorkspaceId, workspaceId)
	common.GetAkeylessPtr(&body.WorkspaceKey, workspaceKey)

	_, _, err = client.GatewayUpdateLogForwardingAzureAnalytics(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update log forwarding settings: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update log forwarding settings: %v", err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGatewayUpdateLogForwardingAzureAnalyticsImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	rOut, err := getGwLogForwardingConfig(d, m)
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
