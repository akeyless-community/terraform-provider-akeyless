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
				Optional:    true,
				Sensitive:   true,
				Description: "pki key file contents encoded using Base64",
			},
			"csr_data_base64": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Certificate Signing Request contents encoded in base64 to generate the certificate with",
			},
			"common_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The common name to be included in the PKI certificate",
			},
			"alt_names": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)",
			},
			"uri_sans": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The URI Subject Alternative Names to be included in the PKI certificate (in a comma-delimited list)",
			},
			"ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Updated certificate lifetime in seconds (must be less than the Certificate Issuer default TTL)",
			},
			"extended_key_usage": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: " A comma-separated list of extended key usage requests which will be used for certificate issuance. Supported values: 'clientauth', 'serverauth'.",
			},
			"data": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "",
			},
			"parent_cert": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "",
			},
			"reading_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "",
			},
			"cert_display_id": {
				Type:        schema.TypeString,
				Computed:    true,
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
	csrDataBase64 := d.Get("csr_data_base64").(string)
	commonName := d.Get("common_name").(string)
	altNames := d.Get("alt_names").(string)
	uriSans := d.Get("uri_sans").(string)
	ttl := d.Get("ttl").(int)
	extendedKeyUsage := d.Get("extended_key_usage").(string)

	body := akeyless.GetPKICertificate{
		CertIssuerName: certIssuerName,
		Token:          &token,
	}
	common.GetAkeylessPtr(&body.KeyDataBase64, keyDataBase64)
	common.GetAkeylessPtr(&body.CsrDataBase64, csrDataBase64)
	common.GetAkeylessPtr(&body.CommonName, commonName)
	common.GetAkeylessPtr(&body.AltNames, altNames)
	common.GetAkeylessPtr(&body.UriSans, uriSans)
	common.GetAkeylessPtr(&body.Ttl, ttl)
	common.GetAkeylessPtr(&body.ExtendedKeyUsage, extendedKeyUsage)

	rOut, res, err := client.GetPKICertificate(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't get pki certificate: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("cant get pki certificate: %v", err)
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
	if rOut.ReadingToken != nil {
		err = d.Set("reading_token", *rOut.ReadingToken)
		if err != nil {
			return err
		}
	}
	if rOut.CertDisplayId != nil {
		err = d.Set("cert_display_id", *rOut.CertDisplayId)
		if err != nil {
			return err
		}
	}

	d.SetId(certIssuerName)
	return nil
}
