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

func resourceGwSessionForwardingSplunk() *schema.Resource {
	return &schema.Resource{
		Description:   "Session Forwarding config for splunk",
		Create:        resourceGwSessionForwardingSplunkUpdate,
		Read:          resourceGwSessionForwardingSplunkRead,
		Update:        resourceGwSessionForwardingSplunkUpdate,
		DeleteContext: resourceGwSessionForwardingSplunkDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGwSessionForwardingSplunkImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("splunk_token"), cty.GetAttrPath("splunk_token_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("tls_certificate"), cty.GetAttrPath("tls_certificate_wo")),
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
			"enable_batch": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable batch forwarding [true/false]",
				Default:     "true",
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
			"splunk_token_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "Splunk token (write-only, not stored in state). Requires Terraform 1.11+. Bump splunk_token_wo_version to change it.",
			},
			"splunk_token_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for splunk_token_wo. Increment to update the value.",
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
			"tls_certificate_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "Splunk tls certificate (PEM format) in a Base64 format (write-only, not stored in state). Requires Terraform 1.11+. Bump tls_certificate_wo_version to change it.",
			},
			"tls_certificate_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for tls_certificate_wo. Increment to update the value.",
			},
		},
	}
}

func resourceGwSessionForwardingSplunkRead(d *schema.ResourceData, m interface{}) error {

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

	config := rOut.SplunkConfig
	if config != nil {
		if config.SplunkUrl != nil {
			err := d.Set("splunk_url", *config.SplunkUrl)
			if err != nil {
				return err
			}
		}
		if config.SplunkToken != nil {
			err := common.SetSecretFromRead(d, "splunk_token", "splunk_token_wo", "splunk_token_wo_version", *config.SplunkToken)
			if err != nil {
				return err
			}
		}
		if config.SplunkSource != nil {
			err := d.Set("source", *config.SplunkSource)
			if err != nil {
				return err
			}
		}
		if config.SplunkSourcetype != nil {
			err := d.Set("source_type", *config.SplunkSourcetype)
			if err != nil {
				return err
			}
		}
		if config.SplunkIndex != nil {
			err := d.Set("index", *config.SplunkIndex)
			if err != nil {
				return err
			}
		}
		if config.SplunkEnableBatch != nil {
			err := d.Set("enable_batch", *config.SplunkEnableBatch)
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
		if config.SplunkTlsCertificate != nil {
			err := common.SetSecretFromRead(d, "tls_certificate", "tls_certificate_wo", "tls_certificate_wo_version", common.Base64Encode(*config.SplunkTlsCertificate))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGwSessionForwardingSplunkUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	enableBatch := d.Get("enable_batch").(string)
	splunkUrl := d.Get("splunk_url").(string)
	splunkToken, err := common.EffectiveSecretValue(d, "splunk_token", "splunk_token_wo")
	if err != nil {
		return err
	}
	source := d.Get("source").(string)
	sourceType := d.Get("source_type").(string)
	index := d.Get("index").(string)
	enableTls := d.Get("enable_tls").(bool)
	tlsCertificate, err := common.EffectiveSecretValue(d, "tls_certificate", "tls_certificate_wo")
	if err != nil {
		return err
	}

	body := akeyless_api.GwUpdateRemoteAccessSessionLogsSplunk{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.EnableBatch, enableBatch)
	common.GetAkeylessPtr(&body.SplunkUrl, splunkUrl)
	common.GetAkeylessPtr(&body.SplunkToken, splunkToken)
	common.GetAkeylessPtr(&body.Source, source)
	common.GetAkeylessPtr(&body.SourceType, sourceType)
	common.GetAkeylessPtr(&body.Index, index)
	common.GetAkeylessPtr(&body.EnableTls, enableTls)
	common.GetAkeylessPtr(&body.TlsCertificate, tlsCertificate)

	_, resp, err := client.GwUpdateRemoteAccessSessionLogsSplunk(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update session forwarding settings", resp, err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGwSessionForwardingSplunkDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGwSessionForwardingSplunkImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	err := resourceGwSessionForwardingSplunkRead(d, m)
	if err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
