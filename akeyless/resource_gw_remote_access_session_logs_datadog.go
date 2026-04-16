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

func resourceGwSessionForwardingDatadog() *schema.Resource {
	return &schema.Resource{
		Description:   "Session Forwarding config for datadog",
		Create:        resourceGwSessionForwardingDatadogUpdate,
		Read:          resourceGwSessionForwardingDatadogRead,
		Update:        resourceGwSessionForwardingDatadogUpdate,
		DeleteContext: resourceGwSessionForwardingDatadogDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGwSessionForwardingDatadogImport,
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
			"host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Datadog host",
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Datadog api key",
			},
			"log_source": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Datadog log source",
				Default:     "use-existing",
			},
			"log_tags": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma-separated list of Datadog log tags formatted as key:value strings",
				Default:     "use-existing",
			},
			"log_service": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Datadog log service",
				Default:     "use-existing",
			},
		},
	}
}

func resourceGwSessionForwardingDatadogRead(d *schema.ResourceData, m interface{}) error {

	rOut, err := getGwRemoteAccessSessionLogsConfig(m)
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

	config := rOut.DatadogConfig
	if config != nil {
		if config.DatadogHost != nil {
			err := d.Set("host", *config.DatadogHost)
			if err != nil {
				return err
			}
		}
		if config.DatadogApiKey != nil {
			err := d.Set("api_key", *config.DatadogApiKey)
			if err != nil {
				return err
			}
		}
		if config.DatadogLogSource != nil {
			err := d.Set("log_source", *config.DatadogLogSource)
			if err != nil {
				return err
			}
		}
		if config.DatadogLogTags != nil {
			err := d.Set("log_tags", *config.DatadogLogTags)
			if err != nil {
				return err
			}
		}
		if config.DatadogLogService != nil {
			err := d.Set("log_service", *config.DatadogLogService)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGwSessionForwardingDatadogUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	host := d.Get("host").(string)
	apiKey := d.Get("api_key").(string)
	logSource := d.Get("log_source").(string)
	logTags := d.Get("log_tags").(string)
	logService := d.Get("log_service").(string)

	body := akeyless_api.GwUpdateRemoteAccessSessionLogsDatadog{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.LogSource, logSource)
	common.GetAkeylessPtr(&body.LogTags, logTags)
	common.GetAkeylessPtr(&body.LogService, logService)

	_, resp, err := client.GwUpdateRemoteAccessSessionLogsDatadog(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update session forwarding settings", resp, err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGwSessionForwardingDatadogDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGwSessionForwardingDatadogImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	err := resourceGwSessionForwardingDatadogRead(d, m)
	if err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
