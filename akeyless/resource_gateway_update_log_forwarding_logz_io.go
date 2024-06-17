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

func resourceGatewayUpdateLogForwardingLogzIo() *schema.Resource {
	return &schema.Resource{
		Description: "Log Forwarding config for logz-io",
		Create:      resourceGatewayUpdateLogForwardingLogzIoUpdate,
		Read:        resourceGatewayUpdateLogForwardingLogzIoRead,
		Update:      resourceGatewayUpdateLogForwardingLogzIoUpdate,
		Delete:      resourceGatewayUpdateLogForwardingLogzIoUpdate,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateLogForwardingLogzIoImport,
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
			"protocol": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Logz-io protocol [tcp/https]",
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
		if config.TargetLogzIoToken != nil && d.Get("logz_io_token").(string) != "" {
			err := d.Set("logz_io_token", *config.TargetLogzIoToken)
			if err != nil {
				return err
			}
		}
		if config.TargetLogzIoProtocol != nil && d.Get("protocol").(string) != "" {
			err := d.Set("protocol", *config.TargetLogzIoProtocol)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGatewayUpdateLogForwardingLogzIoUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	logzIoToken := d.Get("logz_io_token").(string)
	protocol := d.Get("protocol").(string)

	body := akeyless_api.GatewayUpdateLogForwardingLogzIo{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.LogzIoToken, logzIoToken)
	common.GetAkeylessPtr(&body.Protocol, protocol)

	_, _, err := client.GatewayUpdateLogForwardingLogzIo(ctx).Body(body).Execute()
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
			err := d.Set("logz_io_token", *config.TargetLogzIoToken)
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
