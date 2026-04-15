// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayUpdateRemoteAccessDesktopApp() *schema.Resource {
	return &schema.Resource{
		Description:   "Remote access desktop app config",
		Create:        resourceGatewayUpdateRemoteAccessDesktopAppUpdate,
		Read:          resourceGatewayUpdateRemoteAccessDesktopAppRead,
		Update:        resourceGatewayUpdateRemoteAccessDesktopAppUpdate,
		DeleteContext: resourceGatewayUpdateRemoteAccessDesktopAppDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateRemoteAccessDesktopAppImport,
		},
		Schema: map[string]*schema.Schema{
			"desktop_app_ssh_cert_issuer": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Specify the default SSH-CERT-ISSUER that will be used as a fallback for Desktop Application",
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"desktop_app_secure_web_access_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specify the Web Access URL to be used by the Desktop Application",
			},
			"desktop_app_secure_web_proxy": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specify the URL for secure web proxy to be used by the Desktop Application",
			},
		},
	}
}

func resourceGatewayUpdateRemoteAccessDesktopAppUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	desktopAppSecureWebAccessUrl := d.Get("desktop_app_secure_web_access_url").(string)
	desktopAppSecureWebProxy := d.Get("desktop_app_secure_web_proxy").(string)
	desktopAppSshCertIssuer := d.Get("desktop_app_ssh_cert_issuer").(string)

	body := akeyless_api.GatewayUpdateRemoteAccessDesktopApp{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DesktopAppSecureWebAccessUrl, desktopAppSecureWebAccessUrl)
	common.GetAkeylessPtr(&body.DesktopAppSecureWebProxy, desktopAppSecureWebProxy)
	common.GetAkeylessPtr(&body.DesktopAppSshCertIssuer, desktopAppSshCertIssuer)

	_, resp, err := client.GatewayUpdateRemoteAccessDesktopApp(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update remote access desktop app config", resp, err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}
	return nil
}

func resourceGatewayUpdateRemoteAccessDesktopAppRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	rOut, err := getGwRemoteAccessConfig(m)
	if err != nil {
		return err
	}

	desktopApp := rOut.DesktopApp
	if desktopApp != nil {
		if desktopApp.DefaultCertIssuerId != nil && *desktopApp.DefaultCertIssuerId != 0 {
			issuerID := *desktopApp.DefaultCertIssuerId
			issuerName, err := common.GetItemNameByID(client, token, issuerID)
			if err != nil {
				return err
			}
			err = d.Set("desktop_app_ssh_cert_issuer", issuerName)
			if err != nil {
				return err
			}
		}
		if desktopApp.SecureWebAccessUrl != nil {
			err = d.Set("desktop_app_secure_web_access_url", *desktopApp.SecureWebAccessUrl)
			if err != nil {
				return err
			}
		}
		if desktopApp.SecureWebProxyUrl != nil {
			err = d.Set("desktop_app_secure_web_proxy", *desktopApp.SecureWebProxyUrl)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(*rOut.ClusterId)

	return nil
}

func resourceGatewayUpdateRemoteAccessDesktopAppDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateRemoteAccessDesktopAppImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	err := resourceGatewayUpdateRemoteAccessDesktopAppRead(d, m)
	if err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
