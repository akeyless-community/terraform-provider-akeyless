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

func resourceGatewayUpdateLogForwardingSumologic() *schema.Resource {
	return &schema.Resource{
		Description: "Log Forwarding config for sumologic",
		Create:      resourceGatewayUpdateLogForwardingSumologicUpdate,
		Read:        resourceGatewayUpdateLogForwardingSumologicRead,
		Update:      resourceGatewayUpdateLogForwardingSumologicUpdate,
		Delete:      resourceGatewayUpdateLogForwardingSumologicUpdate,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateLogForwardingSumologicImport,
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
		if config.SumoLogicEndpoint != nil && d.Get("endpoint").(string) != "" {
			err := d.Set("endpoint", *config.SumoLogicEndpoint)
			if err != nil {
				return err
			}
		}
		if config.SumoLogicTags != nil && d.Get("sumologic_tags").(string) != common.UseExisting {
			err := d.Set("sumologic_tags", *config.SumoLogicTags)
			if err != nil {
				return err
			}
		}
		if config.SumoLogicHost != nil && d.Get("host").(string) != common.UseExisting {
			err := d.Set("host", *config.SumoLogicHost)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGatewayUpdateLogForwardingSumologicUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	endpoint := d.Get("endpoint").(string)
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

	_, _, err := client.GatewayUpdateLogForwardingSumologic(ctx).Body(body).Execute()
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
			err := d.Set("endpoint", *config.SumoLogicEndpoint)
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
