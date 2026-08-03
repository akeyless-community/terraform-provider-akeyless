// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceGatewayUpdateTlsCert() *schema.Resource {
	return &schema.Resource{
		Description:   "TLS certificate config for gateway",
		Create:        resourceGatewayUpdateTlsCertUpdate,
		Read:          resourceGatewayUpdateTlsCertRead,
		Update:        resourceGatewayUpdateTlsCertUpdate,
		DeleteContext: resourceGatewayUpdateTlsCertDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateTlsCertImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("cert_data"), cty.GetAttrPath("cert_data_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("key_data"), cty.GetAttrPath("key_data_wo")),
		},
		Schema: map[string]*schema.Schema{
			"cert_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "TLS certificate data (PEM format)",
			},
			"cert_data_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "TLS certificate data (PEM format) (write-only, not stored in state). Requires Terraform 1.11+. Bump cert_data_wo_version to change it.",
			},
			"cert_data_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for cert_data_wo. Increment to update the value.",
			},
			"key_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "TLS private key data (PEM format)",
			},
			"key_data_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "TLS private key data (PEM format) (write-only, not stored in state). Requires Terraform 1.11+. Bump key_data_wo_version to change it.",
			},
			"key_data_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for key_data_wo. Increment to update the value.",
			},
			"expiration_event_in": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "How many days before the TLS certificate expiration to trigger an expiration event (e.g. [60, 30, 10])",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourceGatewayUpdateTlsCertRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	body := akeyless_api.GatewayGetConfig{
		Token: &token,
	}

	rOut, resp, err := client.GatewayGetConfig(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't get TLS cert config", resp, err)
	}

	if rOut.General != nil {
		tlsConf := *rOut.General

		if tlsConf.TlsCert != nil {
			err := common.SetSecretFromRead(d, "cert_data", "cert_data_wo", "cert_data_wo_version", common.Base64Encode(*tlsConf.TlsCert))
			if err != nil {
				return err
			}
		}
		if tlsConf.TlsKey != nil {
			err := common.SetSecretFromRead(d, "key_data", "key_data_wo", "key_data_wo_version", common.Base64Encode(*tlsConf.TlsKey))
			if err != nil {
				return err
			}
		}
		if tlsConf.TlsCertExpirationEvents != nil {
			err := d.Set("expiration_event_in", common.ReadExpirationEventInParam(tlsConf.TlsCertExpirationEvents))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGatewayUpdateTlsCertUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	certData, err := common.EffectiveSecretValue(d, "cert_data", "cert_data_wo")
	if err != nil {
		return err
	}
	keyData, err := common.EffectiveSecretValue(d, "key_data", "key_data_wo")
	if err != nil {
		return err
	}

	body := akeyless_api.GatewayUpdateTlsCert{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.CertData, certData)
	common.GetAkeylessPtr(&body.KeyData, keyData)

	expirationEventInRaw := d.Get("expiration_event_in").([]interface{})
	if len(expirationEventInRaw) > 0 {
		expirationEventIn := make([]string, 0, len(expirationEventInRaw))
		for _, v := range expirationEventInRaw {
			expirationEventIn = append(expirationEventIn, v.(string))
		}
		body.ExpirationEventIn = expirationEventIn
	}

	_, resp, err := client.GatewayUpdateTlsCert(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update TLS cert config", resp, err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGatewayUpdateTlsCertDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateTlsCertImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	return []*schema.ResourceData{d}, nil
}
