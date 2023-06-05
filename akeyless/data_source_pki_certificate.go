package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGetPKICertificate() *schema.Resource {
	return &schema.Resource{
		Description: "Generates PKI certificate data source",
		Read:        dataSourceGetPKICertificateRead,
		Schema: map[string]*schema.Schema{
			"cert_issuer_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the PKI certificate issuer",
			},
			"key_data_base64": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "pki key file contents encoded using Base64. If this option is used, the certificate will be printed to stdout",
			},
			"common_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The common name to be included in the PKI certificate",
			},
			"alt_names": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)",
			},
			"uri_sans": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)",
			},
			"path": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"data": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"parent_cert": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
		},
	}
}

func dataSourceGetPKICertificateRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	certIssuerName := d.Get("cert_issuer_name").(string)
	keyDataBase64 := d.Get("key_data_base64").(string)
	commonName := d.Get("common_name").(string)
	altNames := d.Get("alt_names").(string)
	uriSans := d.Get("uri_sans").(string)

	body := akeyless.GetPKICertificate{
		CertIssuerName: certIssuerName,
		Token:          &token,
	}
	common.GetAkeylessPtr(&body.KeyDataBase64, keyDataBase64)
	common.GetAkeylessPtr(&body.CommonName, commonName)
	common.GetAkeylessPtr(&body.AltNames, altNames)
	common.GetAkeylessPtr(&body.UriSans, uriSans)

	rOut, res, err := client.GetPKICertificate(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't get value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}

	if rOut.Path != nil {
		err = d.Set("path", *rOut.Path)
		if err != nil {
			return err
		}
	}
	if rOut.Data != nil {
		err = d.Set("data", *rOut.Data)
		if err != nil {
			return err
		}
	}
	if rOut.ParentCert != nil {
		err = d.Set("parent_cert", *rOut.ParentCert)
		if err != nil {
			return err
		}
	}

	d.SetId(certIssuerName)
	return nil
}
