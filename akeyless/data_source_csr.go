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

func dataSourceGenerateCsr() *schema.Resource {
	return &schema.Resource{
		Description: "Generate a new CSR data source",
		Read:        dataSourceGenerateCsrRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "classic key name",
				ForceNew:    true,
			},
			"common_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "common name to be included in the CSR certificate",
			},
			"generate_key": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "generate a new classic key for the csr",
			},
			"alg": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "algorithm (RSA/Elliptic-curve) to use for generating the new key",
			},
			"certificate_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "certificate type to be included in the CSR certificate (ssl-client/ssl-server/certificate-signing)",
			},
			"critical": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "add critical to the key usage extension (will be false if not added)",
			},
			"org": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "organization to be included in the CSR",
			},
			"dep": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "department to be included in the CSR",
			},
			"city": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "city to be included in the CSR",
			},
			"state": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "state to be included in the CSR",
			},
			"country": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "country to be included in the CSR",
			},
			"alt_names": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "a comma-separated list of dns alternative names",
			},
			"email_addresses": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "a comma-separated list of email addresses alternative names",
			},
			"ip_addresses": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "a comma-separated list of ip addresses alternative names",
			},
			"uri_sans": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "a comma-separated list of uri alternative names",
			},
			"data": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "",
			},
		},
	}
}

func dataSourceGenerateCsrRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	commonName := d.Get("common_name").(string)
	generateKey := d.Get("generate_key").(bool)
	alg := d.Get("alg").(string)
	certificateType := d.Get("certificate_type").(string)
	critical := d.Get("critical").(bool)
	org := d.Get("org").(string)
	dep := d.Get("dep").(string)
	city := d.Get("city").(string)
	state := d.Get("state").(string)
	country := d.Get("country").(string)
	altNames := d.Get("alt_names").(string)
	emailAddresses := d.Get("email_addresses").(string)
	ipAddresses := d.Get("ip_addresses").(string)
	uriSans := d.Get("uri_sans").(string)

	body := akeyless.GenerateCsr{
		Name:       name,
		CommonName: commonName,
		Token:      &token,
	}
	common.GetAkeylessPtr(&body.GenerateKey, generateKey)
	common.GetAkeylessPtr(&body.Alg, alg)
	common.GetAkeylessPtr(&body.CertificateType, certificateType)
	common.GetAkeylessPtr(&body.Critical, critical)
	common.GetAkeylessPtr(&body.Org, org)
	common.GetAkeylessPtr(&body.Dep, dep)
	common.GetAkeylessPtr(&body.City, city)
	common.GetAkeylessPtr(&body.State, state)
	common.GetAkeylessPtr(&body.Country, country)
	common.GetAkeylessPtr(&body.AltNames, altNames)
	common.GetAkeylessPtr(&body.EmailAddresses, emailAddresses)
	common.GetAkeylessPtr(&body.IpAddresses, ipAddresses)
	common.GetAkeylessPtr(&body.UriSans, uriSans)

	rOut, res, err := client.GenerateCsr(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't generate csr: %v, %v", string(apiErr.Body()), err)
		}
		return fmt.Errorf("can't generate csr: %v", err)
	}
	err = d.Set("data", *rOut.Data)
	if err != nil {
		return err
	}

	d.SetId(name)
	return nil
}
