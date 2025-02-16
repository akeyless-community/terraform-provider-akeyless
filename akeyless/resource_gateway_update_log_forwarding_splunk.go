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
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayUpdateLogForwardingSplunk() *schema.Resource {
	return &schema.Resource{
		Description:   "Log Forwarding config for splunk",
		Create:        resourceGatewayUpdateLogForwardingSplunkUpdate,
		Read:          resourceGatewayUpdateLogForwardingSplunkRead,
		Update:        resourceGatewayUpdateLogForwardingSplunkUpdate,
		DeleteContext: resourceGatewayUpdateLogForwardingSplunkDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateLogForwardingSplunkImport,
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
			"splunk_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Splunk server URL",
			},
			"splunk_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Splunk token",
			},
			"source": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Splunk source",
				Default:     "use-existing",
			},
			"source_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Splunk source type",
				Default:     "use-existing",
			},
			"index": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Splunk index",
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
				Description: "Splunk tls certificate (PEM format) in a Base64 format",
				Default:     "use-existing",
			},
		},
	}
}

func resourceGatewayUpdateLogForwardingSplunkRead(d *schema.ResourceData, m interface{}) error {

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

	config := rOut.SplunkConfig
	if config != nil {
		if config.SplunkUrl != nil && d.Get("splunk_url").(string) != "" {
			err := d.Set("splunk_url", *config.SplunkUrl)
			if err != nil {
				return err
			}
		}
		if config.SplunkToken != nil && d.Get("splunk_token").(string) != "" {
			err := d.Set("splunk_token", *config.SplunkToken)
			if err != nil {
				return err
			}
		}
		if config.SplunkSource != nil && d.Get("source").(string) != common.UseExisting {
			err := d.Set("source", *config.SplunkSource)
			if err != nil {
				return err
			}
		}
		if config.SplunkSourcetype != nil && d.Get("source_type").(string) != common.UseExisting {
			err := d.Set("source_type", *config.SplunkSourcetype)
			if err != nil {
				return err
			}
		}
		if config.SplunkIndex != nil && d.Get("index").(string) != "" {
			err := d.Set("index", *config.SplunkIndex)
			if err != nil {
				return err
			}
		}
		if config.SplunkEnableTls != nil {
			err := d.Set("enable_tls", *config.SplunkEnableTls)
			if err != nil {
				return err
			}
		}
		if config.SplunkTlsCertificate != nil && d.Get("tls_certificate").(string) != common.UseExisting {
			err := d.Set("tls_certificate", common.Base64Encode(*config.SplunkTlsCertificate))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGatewayUpdateLogForwardingSplunkUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	splunkUrl := d.Get("splunk_url").(string)
	splunkToken := d.Get("splunk_token").(string)
	source := d.Get("source").(string)
	sourceType := d.Get("source_type").(string)
	index := d.Get("index").(string)
	enableTls := d.Get("enable_tls").(bool)
	tlsCertificate := d.Get("tls_certificate").(string)

	body := akeyless_api.GatewayUpdateLogForwardingSplunk{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.SplunkUrl, splunkUrl)
	common.GetAkeylessPtr(&body.SplunkToken, splunkToken)
	common.GetAkeylessPtr(&body.Source, source)
	common.GetAkeylessPtr(&body.SourceType, sourceType)
	common.GetAkeylessPtr(&body.Index, index)
	common.GetAkeylessPtr(&body.EnableTls, enableTls)
	common.GetAkeylessPtr(&body.TlsCertificate, tlsCertificate)

	_, _, err := client.GatewayUpdateLogForwardingSplunk(ctx).Body(body).Execute()
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

func resourceGatewayUpdateLogForwardingSplunkDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateLogForwardingSplunkImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

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

	config := rOut.SplunkConfig
	if config != nil {
		if config.SplunkUrl != nil {
			err := d.Set("splunk_url", *config.SplunkUrl)
			if err != nil {
				return nil, err
			}
		}
		if config.SplunkToken != nil {
			err := d.Set("splunk_token", *config.SplunkToken)
			if err != nil {
				return nil, err
			}
		}
		if config.SplunkSource != nil {
			err := d.Set("source", *config.SplunkSource)
			if err != nil {
				return nil, err
			}
		}
		if config.SplunkSourcetype != nil {
			err := d.Set("source_type", *config.SplunkSourcetype)
			if err != nil {
				return nil, err
			}
		}
		if config.SplunkIndex != nil {
			err := d.Set("index", *config.SplunkIndex)
			if err != nil {
				return nil, err
			}
		}
		if config.SplunkEnableTls != nil {
			err := d.Set("enable_tls", *config.SplunkEnableTls)
			if err != nil {
				return nil, err
			}
		}
		if config.SplunkTlsCertificate != nil {
			err := d.Set("tls_certificate", common.Base64Encode(*config.SplunkTlsCertificate))
			if err != nil {
				return nil, err
			}
		}
	}

	return []*schema.ResourceData{d}, nil
}
