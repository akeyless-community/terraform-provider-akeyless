package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGetSSHCertificate() *schema.Resource {
	return &schema.Resource{
		Description: "Generates SSH certificate data source",
		Read:        dataSourceGetSSHCertificateRead,
		Schema: map[string]*schema.Schema{
			"cert_issuer_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the SSH certificate issuer",
			},
			"cert_username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The username to sign in the SSH certificate (use a comma-separated list for more than one username)",
			},
			"public_key_data": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "SSH public key file contents",
			},
			"ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Updated certificate lifetime in seconds (must be less than the Certificate Issuer default TTL)",
			},
			"legacy_signing_alg_name": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Set this option to output legacy ('ssh-rsa-cert-v01@openssh.com') signing algorithm name in the certificate.",
			},
			"data": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "",
			},
		},
	}
}

func dataSourceGetSSHCertificateRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	certUsername := d.Get("cert_username").(string)
	certIssuerName := d.Get("cert_issuer_name").(string)
	publicKeyData := d.Get("public_key_data").(string)
	ttl := d.Get("ttl").(int)
	legacySigningAlgName := d.Get("legacy_signing_alg_name").(bool)

	body := akeyless_api.GetSSHCertificate{
		CertUsername:   certUsername,
		CertIssuerName: certIssuerName,
		Token:          &token,
	}
	common.GetAkeylessPtr(&body.PublicKeyData, publicKeyData)
	common.GetAkeylessPtr(&body.Ttl, ttl)
	common.GetAkeylessPtr(&body.LegacySigningAlgName, legacySigningAlgName)

	rOut, res, err := client.GetSSHCertificate(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("failed to get ssh certificate: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to get ssh certificate: %w", err)
	}

	if rOut.Data != nil {
		err = d.Set("data", *rOut.Data)
		if err != nil {
			return err
		}
	}

	d.SetId(certUsername)
	return nil
}
