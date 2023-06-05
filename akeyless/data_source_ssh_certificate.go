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

func dataSourceGetSSHCertificate() *schema.Resource {
	return &schema.Resource{
		Description: "Generates SSH certificate data source",
		Read:        dataSourceGetSSHCertificateRead,
		Schema: map[string]*schema.Schema{
			"cert_username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The username to sign in the SSH certificate (use a comma-separated list for more than one username)",
			},
			"cert_issuer_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the SSH certificate issuer",
			},
			"public_key_data": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "SSH public key file contents. If this option is used, the certificate will be printed to stdout",
			},
			"data": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"path": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
		},
	}
}

func dataSourceGetSSHCertificateRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	certUsername := d.Get("cert_username").(string)
	certIssuerName := d.Get("cert_issuer_name").(string)
	publicKeyData := d.Get("public_key_data").(string)

	body := akeyless.GetSSHCertificate{
		CertUsername:   certUsername,
		CertIssuerName: certIssuerName,
		Token:          &token,
	}
	common.GetAkeylessPtr(&body.PublicKeyData, publicKeyData)

	rOut, res, err := client.GetSSHCertificate(ctx).Body(body).Execute()
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

	if rOut.Data != nil {
		err = d.Set("data", *rOut.Data)
		if err != nil {
			return err
		}
	}
	if rOut.Path != nil {
		err = d.Set("path", *rOut.Path)
		if err != nil {
			return err
		}
	}

	d.SetId(certUsername)
	return nil
}
