package akeyless

import (
	"context"
	"errors"
	"fmt"

	"github.com/akeylesslabs/akeyless-go/v3"
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
			"display_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Certificate display ID",
			},
			"version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Certificate version",
			},
			"cert_issuer_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The parent PKI Certificate Issuer's name of the certificate, required when used with display-id and token",
			},
			"issuance_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Token for getting the issued certificate",
			},
			"ignore_cache": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Retrieve the Secret value without checking the Gateway's cache [true/false]. This flag is only relevant when using the RestAPI",
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
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	displayId := d.Get("display_id").(string)
	version := d.Get("version").(int)
	certIssuerName := d.Get("cert_issuer_name").(string)
	issuanceToken := d.Get("issuance_token").(string)
	ignoreCache := d.Get("ignore_cache").(string)

	body := akeyless.GetCertificateValue{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Name, name)
	common.GetAkeylessPtr(&body.DisplayId, displayId)
	common.GetAkeylessPtr(&body.Version, version)
	common.GetAkeylessPtr(&body.CertIssuerName, certIssuerName)
	common.GetAkeylessPtr(&body.IssuanceToken, issuanceToken)
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

	if name != "" {
		d.SetId(name)
	} else {
		d.SetId(displayId)
	}

	return nil
}
