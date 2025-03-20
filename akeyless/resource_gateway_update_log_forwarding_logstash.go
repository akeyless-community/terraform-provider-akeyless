// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayUpdateLogForwardingLogstash() *schema.Resource {
	return &schema.Resource{
		Description:   "Log Forwarding config for logstash",
		Create:        resourceGatewayUpdateLogForwardingLogstashUpdate,
		Read:          resourceGatewayUpdateLogForwardingLogstashRead,
		Update:        resourceGatewayUpdateLogForwardingLogstashUpdate,
		DeleteContext: resourceGatewayUpdateLogForwardingLogstashDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateLogForwardingLogstashImport,
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
			"dns": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Logstash dns",
			},
			"protocol": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Logstash protocol [tcp/udp]",
			},
			"enable_tls": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable tls",
			},
			"tls_certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Logstash tls certificate (PEM format) in a Base64 format",
				Default:     "use-existing",
			},
		},
	}
}

func resourceGatewayUpdateLogForwardingLogstashRead(d *schema.ResourceData, m interface{}) error {

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

	config := rOut.LogstashConfig
	if config != nil {
		if config.LogstashDns != nil && d.Get("dns").(string) != "" {
			err := d.Set("dns", *config.LogstashDns)
			if err != nil {
				return err
			}
		}
		if config.LogstashProtocol != nil && d.Get("protocol").(string) != "" {
			err := d.Set("protocol", *config.LogstashProtocol)
			if err != nil {
				return err
			}
		}
		if config.LogstashEnableTls != nil {
			err := d.Set("enable_tls", *config.LogstashEnableTls)
			if err != nil {
				return err
			}
		}
		if config.LogstashTlsCertificate != nil && d.Get("tls_certificate").(string) != common.UseExisting {
			err := d.Set("tls_certificate", common.Base64Encode(*config.LogstashTlsCertificate))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGatewayUpdateLogForwardingLogstashUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	dns := d.Get("dns").(string)
	protocol := d.Get("protocol").(string)
	enableTls := d.Get("enable_tls").(bool)
	tlsCertificate := d.Get("tls_certificate").(string)

	body := akeyless_api.GatewayUpdateLogForwardingLogstash{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.Dns, dns)
	common.GetAkeylessPtr(&body.Protocol, protocol)
	common.GetAkeylessPtr(&body.EnableTls, enableTls)
	common.GetAkeylessPtr(&body.TlsCertificate, tlsCertificate)

	_, _, err := client.GatewayUpdateLogForwardingLogstash(ctx).Body(body).Execute()
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

func resourceGatewayUpdateLogForwardingLogstashDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateLogForwardingLogstashImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

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

	config := rOut.LogstashConfig
	if config != nil {
		if config.LogstashDns != nil {
			err := d.Set("dns", *config.LogstashDns)
			if err != nil {
				return nil, err
			}
		}
		if config.LogstashProtocol != nil {
			err := d.Set("protocol", *config.LogstashProtocol)
			if err != nil {
				return nil, err
			}
		}
		if config.LogstashEnableTls != nil {
			err := d.Set("enable_tls", *config.LogstashEnableTls)
			if err != nil {
				return nil, err
			}
		}
		if config.LogstashTlsCertificate != nil {
			err := d.Set("tls_certificate", common.Base64Encode(*config.LogstashTlsCertificate))
			if err != nil {
				return nil, err
			}
		}
	}

	return []*schema.ResourceData{d}, nil
}
