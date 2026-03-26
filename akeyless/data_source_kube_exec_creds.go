package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGetKubeExecCreds() *schema.Resource {
	return &schema.Resource{
		Description: "Get credentials for authentication with Kubernetes cluster based on a PKI Cert Issuer data source",
		Read:        dataSourceGetKubeExecCredsRead,
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
				Sensitive:   true,
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
			"csr_data_base64": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Certificate Signing Request contents encoded in base64 to generate the certificate with",
			},
			"extended_key_usage": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A comma-separated list of extended key usage requests which will be used for certificate issuance. Supported values: 'clientauth', 'serverauth', 'codesigning'",
			},
			"extra_extensions": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A json string that defines the requested extra extensions for the certificate",
			},
			"ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Updated certificate lifetime in seconds (must be less than the Certificate Issuer default TTL)",
			},
			"max_path_len": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "The maximum path length for the generated certificate. -1 means unlimited unless the signing certificate has a maximum path length set",
			},
			"kind": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "The kind of the Kubernetes exec credential",
			},
			"api_version": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "The API version of the Kubernetes exec credential",
			},
			"client_certificate_data": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "The client certificate data for Kubernetes authentication",
			},
			"client_key_data": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "The client key data for Kubernetes authentication",
			},
			"parent_certificate_data": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "The parent certificate data for Kubernetes authentication",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceGetKubeExecCredsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	certIssuerName := d.Get("cert_issuer_name").(string)
	keyDataBase64 := d.Get("key_data_base64").(string)
	commonName := d.Get("common_name").(string)
	altNames := d.Get("alt_names").(string)
	uriSans := d.Get("uri_sans").(string)
	csrDataBase64 := d.Get("csr_data_base64").(string)
	extendedKeyUsage := d.Get("extended_key_usage").(string)
	extraExtensions := d.Get("extra_extensions").(string)
	ttl := d.Get("ttl").(string)
	maxPathLen := d.Get("max_path_len").(int)

	body := akeyless_api.GetKubeExecCreds{
		CertIssuerName: certIssuerName,
		Token:          &token,
	}
	common.GetAkeylessPtr(&body.KeyDataBase64, keyDataBase64)
	common.GetAkeylessPtr(&body.CommonName, commonName)
	common.GetAkeylessPtr(&body.AltNames, altNames)
	common.GetAkeylessPtr(&body.UriSans, uriSans)
	common.GetAkeylessPtr(&body.CsrDataBase64, csrDataBase64)
	common.GetAkeylessPtr(&body.ExtendedKeyUsage, extendedKeyUsage)
	common.GetAkeylessPtr(&body.ExtraExtensions, extraExtensions)
	common.GetAkeylessPtr(&body.Ttl, ttl)
	if maxPathLen != 0 {
		body.MaxPathLen = &[]int64{int64(maxPathLen)}[0]
	}

	rOut, res, err := client.GetKubeExecCreds(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}
	if rOut.Kind != nil {
		err = d.Set("kind", *rOut.Kind)
		if err != nil {
			return err
		}
	}
	if rOut.ApiVersion != nil {
		err = d.Set("api_version", *rOut.ApiVersion)
		if err != nil {
			return err
		}
	}

	err = d.Set("client_certificate_data", rOut.Status.GetClientCertificateData())
	if err != nil {
		return err
	}

	err = d.Set("client_key_data", rOut.Status.GetClientKeyData())
	if err != nil {
		return err
	}

	err = d.Set("parent_certificate_data", rOut.Status.GetParentCertificateData())
	if err != nil {
		return err
	}

	d.SetId(certIssuerName)
	return nil
}
