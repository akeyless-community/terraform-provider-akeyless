package akeyless

import (
	"context"
	"errors"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceCertificate() *schema.Resource {
	return &schema.Resource{
		Description: "Certificate data source",
		Read:        dataSourceGetCertificateValueRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Certificate name",
			},
			"version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Certificate version",
			},
			"ignore_cache": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Retrieve the Secret value without checking the Gateway's cache [true/false]",
				Default:     "false",
			},
			"certificate_pem": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The certificate value in pem format",
			},
			"private_key_pem": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The private key value in pem format",
			},
		},
	}
}

func dataSourceGetCertificateValueRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	version := d.Get("version").(int)
	ignoreCache := d.Get("ignore_cache").(string)

	body := akeyless_api.GetCertificateValue{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Name, name)
	common.GetAkeylessPtr(&body.Version, version)
	common.GetAkeylessPtr(&body.IgnoreCache, ignoreCache)

	rOut, _, err := client.GetCertificateValue(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't get certificate value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get certificate value: %w", err)
	}

	if rOut.CertificatePem != nil {
		err := d.Set("certificate_pem", *rOut.CertificatePem)
		if err != nil {
			return err
		}
	}
	if rOut.PrivateKeyPem != nil {
		err := d.Set("private_key_pem", *rOut.PrivateKeyPem)
		if err != nil {
			return err
		}
	}

	d.SetId(name)

	return nil
}
