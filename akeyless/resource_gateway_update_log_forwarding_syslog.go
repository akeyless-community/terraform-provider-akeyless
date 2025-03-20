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

func resourceGatewayUpdateLogForwardingSyslog() *schema.Resource {
	return &schema.Resource{
		Description:   "Log Forwarding config for syslog",
		Create:        resourceGatewayUpdateLogForwardingSyslogUpdate,
		Read:          resourceGatewayUpdateLogForwardingSyslogRead,
		Update:        resourceGatewayUpdateLogForwardingSyslogUpdate,
		DeleteContext: resourceGatewayUpdateLogForwardingSyslogDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateLogForwardingSyslogImport,
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
			"network": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Syslog network [tcp/udp]",
				Default:     "tcp",
			},
			"host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Syslog host",
			},
			"target_tag": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Syslog target tag",
				Default:     "use-existing",
			},
			"formatter": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Syslog formatter [text/cef]",
				Default:     "text",
			},
			"enable_tls": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable tls relevant only for network type TCP",
			},
			"tls_certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Syslog tls certificate (PEM format) in a Base64 format",
				Default:     "use-existing",
			},
		},
	}
}

func resourceGatewayUpdateLogForwardingSyslogRead(d *schema.ResourceData, m interface{}) error {

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

	config := rOut.SyslogConfig
	if config != nil {
		if config.SyslogNetwork != nil && d.Get("network") != "" {
			err := d.Set("network", *config.SyslogNetwork)
			if err != nil {
				return err
			}
		}
		if config.SyslogHost != nil && d.Get("host") != "" {
			err := d.Set("host", *config.SyslogHost)
			if err != nil {
				return err
			}
		}
		if config.SyslogTargetTag != nil && d.Get("target_tag").(string) != common.UseExisting {
			err := d.Set("target_tag", *config.SyslogTargetTag)
			if err != nil {
				return err
			}
		}
		if config.SyslogFormatter != nil && d.Get("formatter") != "" {
			err := d.Set("formatter", *config.SyslogFormatter)
			if err != nil {
				return err
			}
		}
		if config.SyslogEnableTls != nil {
			err := d.Set("enable_tls", *config.SyslogEnableTls)
			if err != nil {
				return err
			}
		}
		if config.SyslogTlsCertificate != nil && d.Get("tls_certificate").(string) != common.UseExisting {
			err := d.Set("tls_certificate", common.Base64Encode(*config.SyslogTlsCertificate))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGatewayUpdateLogForwardingSyslogUpdate(d *schema.ResourceData, m interface{}) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	network := d.Get("network").(string)
	host := d.Get("host").(string)
	targetTag := d.Get("target_tag").(string)
	formatter := d.Get("formatter").(string)
	enableTls := d.Get("enable_tls").(bool)
	tlsCertificate := d.Get("tls_certificate").(string)

	body := akeyless_api.GatewayUpdateLogForwardingSyslog{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.Network, network)
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.TargetTag, targetTag)
	common.GetAkeylessPtr(&body.Formatter, formatter)
	common.GetAkeylessPtr(&body.EnableTls, enableTls)
	common.GetAkeylessPtr(&body.TlsCertificate, tlsCertificate)

	_, _, err := client.GatewayUpdateLogForwardingSyslog(ctx).Body(body).Execute()
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

func resourceGatewayUpdateLogForwardingSyslogDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateLogForwardingSyslogImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

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

	config := rOut.SyslogConfig
	if config != nil {
		if config.SyslogNetwork != nil {
			err := d.Set("network", *config.SyslogNetwork)
			if err != nil {
				return nil, err
			}
		}
		if config.SyslogHost != nil {
			err := d.Set("host", *config.SyslogHost)
			if err != nil {
				return nil, err
			}
		}
		if config.SyslogTargetTag != nil {
			err := d.Set("target_tag", *config.SyslogTargetTag)
			if err != nil {
				return nil, err
			}
		}
		if config.SyslogFormatter != nil {
			err := d.Set("formatter", *config.SyslogFormatter)
			if err != nil {
				return nil, err
			}
		}
		if config.SyslogEnableTls != nil {
			err := d.Set("enable_tls", *config.SyslogEnableTls)
			if err != nil {
				return nil, err
			}
		}
		if config.SyslogTlsCertificate != nil {
			err := d.Set("tls_certificate", common.Base64Encode(*config.SyslogTlsCertificate))
			if err != nil {
				return nil, err
			}
		}
	}

	return []*schema.ResourceData{d}, nil
}

func getGwLogForwardingConfig(m interface{}) (akeyless_api.LogForwardingConfigPart, error) {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	body := akeyless_api.GatewayGetLogForwarding{
		Token: &token,
	}

	rOut, _, err := client.GatewayGetLogForwarding(ctx).Body(body).Execute()
	if err != nil {
		var apiErr akeyless_api.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			return akeyless_api.LogForwardingConfigPart{}, fmt.Errorf("can't get log forwarding settings: %v", string(apiErr.Body()))
		}
		return akeyless_api.LogForwardingConfigPart{}, fmt.Errorf("can't get log forwarding settings: %w", err)
	}

	return rOut, nil
}
