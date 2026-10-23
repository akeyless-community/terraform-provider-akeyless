package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
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
			"format": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Format to download the certificate in [pem/pfx/jks], pfx/jks require a password",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Password to protect the pfx/jks file, required when format is pfx or jks",
			},
			"include_private_key": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, includes the private key in the pfx/jks file, only relevant when format is pfx or jks",
			},
			"leaf_only": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, downloads only the leaf certificate instead of the full chain, only available for certificates issued with split certificate chain enabled",
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
			"encoded_certificate": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The base64 encoded certificate file, returned when format is pfx or jks",
			},
		},
	}
}

func dataSourceGetCertificateValueRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	version := d.Get("version").(int)
	ignoreCache := d.Get("ignore_cache").(string)
	format := d.Get("format").(string)
	password := d.Get("password").(string)
	includePrivateKey := d.Get("include_private_key").(bool)
	leafOnly := d.Get("leaf_only").(bool)

	body := akeyless_api.GetCertificateValue{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Name, name)
	common.GetAkeylessPtr(&body.Version, version)
	common.GetAkeylessPtr(&body.IgnoreCache, ignoreCache)
	common.GetAkeylessPtr(&body.Format, format)
	common.GetAkeylessPtr(&body.Password, password)
	common.GetAkeylessPtr(&body.IncludePrivateKey, includePrivateKey)
	common.GetAkeylessPtr(&body.LeafOnly, leafOnly)

	rOut, res, err := client.GetCertificateValue(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get certificate value", res, err)
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
	if rOut.EncodedCertificate != nil {
		err := d.Set("encoded_certificate", *rOut.EncodedCertificate)
		if err != nil {
			return err
		}
	}

	d.SetId(name)

	return nil
}
