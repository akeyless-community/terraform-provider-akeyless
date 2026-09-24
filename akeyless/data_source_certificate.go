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
			"include_private_key": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Include the private key in the certificate value response",
			},
			"leaf_only": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Return only the leaf certificate",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Password for the certificate private key",
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
	includePrivateKey := d.Get("include_private_key").(bool)
	leafOnly := d.Get("leaf_only").(bool)
	password := d.Get("password").(string)

	body := akeyless_api.GetCertificateValue{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Name, name)
	common.GetAkeylessPtr(&body.Version, version)
	common.GetAkeylessPtr(&body.IgnoreCache, ignoreCache)
	if _, ok := d.GetOkExists("include_private_key"); ok {
		common.GetAkeylessPtr(&body.IncludePrivateKey, includePrivateKey)
	}
	if _, ok := d.GetOkExists("leaf_only"); ok {
		common.GetAkeylessPtr(&body.LeafOnly, leafOnly)
	}
	if _, ok := d.GetOk("password"); ok {
		common.GetAkeylessPtr(&body.Password, password)
	}

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

	d.SetId(name)

	return nil
}
