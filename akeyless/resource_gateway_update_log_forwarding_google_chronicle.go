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

func resourceGatewayUpdateLogForwardingGoogleChronicle() *schema.Resource {
	return &schema.Resource{
		Description: "Log Forwarding config for google-chronicle",
		Create:      resourceGatewayUpdateLogForwardingGoogleChronicleUpdate,
		Read:        resourceGatewayUpdateLogForwardingGoogleChronicleRead,
		Update:      resourceGatewayUpdateLogForwardingGoogleChronicleUpdate,
		Delete:      resourceGatewayUpdateLogForwardingGoogleChronicleUpdate,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateLogForwardingGoogleChronicleImport,
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
			"gcp_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Base64-encoded service account private key text",
			},
			"customer_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Google chronicle customer id",
			},
			"region": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Google chronicle region [eu_multi_region/london/us_multi_region/singapore/tel_aviv]",
			},
			"log_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Google chronicle log type",
			},
		},
	}
}

func resourceGatewayUpdateLogForwardingGoogleChronicleRead(d *schema.ResourceData, m interface{}) error {

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

	config := rOut.GoogleChronicleConfig
	if config != nil {
		if config.ServiceAccountKey != nil && d.Get("gcp_key").(string) != "" {
			err := d.Set("gcp_key", *config.ServiceAccountKey)
			if err != nil {
				return err
			}
		}
		if config.CustomerId != nil && d.Get("customer_id").(string) != "" {
			err := d.Set("customer_id", *config.CustomerId)
			if err != nil {
				return err
			}
		}
		if config.Region != nil && d.Get("region").(string) != "" {
			err := d.Set("region", *config.Region)
			if err != nil {
				return err
			}
		}
		if config.LogType != nil && d.Get("log_type").(string) != "" {
			err := d.Set("log_type", *config.LogType)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGatewayUpdateLogForwardingGoogleChronicleUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	gcpKey := d.Get("gcp_key").(string)
	customerId := d.Get("customer_id").(string)
	region := d.Get("region").(string)
	logType := d.Get("log_type").(string)

	body := akeyless_api.GatewayUpdateLogForwardingGoogleChronicle{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.GcpKey, gcpKey)
	common.GetAkeylessPtr(&body.CustomerId, customerId)
	common.GetAkeylessPtr(&body.Region, region)
	common.GetAkeylessPtr(&body.LogType, logType)

	_, _, err := client.GatewayUpdateLogForwardingGoogleChronicle(ctx).Body(body).Execute()
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

func resourceGatewayUpdateLogForwardingGoogleChronicleImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

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

	config := rOut.GoogleChronicleConfig
	if config != nil {
		if config.ServiceAccountKey != nil {
			err := d.Set("gcp_key", *config.ServiceAccountKey)
			if err != nil {
				return nil, err
			}
		}
		if config.CustomerId != nil {
			err := d.Set("customer_id", *config.CustomerId)
			if err != nil {
				return nil, err
			}
		}
		if config.Region != nil {
			err := d.Set("region", *config.Region)
			if err != nil {
				return nil, err
			}
		}
		if config.LogType != nil {
			err := d.Set("log_type", *config.LogType)
			if err != nil {
				return nil, err
			}
		}
	}

	return []*schema.ResourceData{d}, nil
}
