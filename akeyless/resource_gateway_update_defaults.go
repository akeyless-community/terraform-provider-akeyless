// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayUpdateDefaults() *schema.Resource {
	return &schema.Resource{
		Description:   "Defaults settings",
		Create:        resourceGatewayUpdateDefaultsUpdate,
		Read:          resourceGatewayUpdateDefaultsRead,
		Update:        resourceGatewayUpdateDefaultsUpdate,
		DeleteContext: resourceGatewayUpdateDefaultsDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateDefaultsImport,
		},
		Schema: map[string]*schema.Schema{
			"saml_access_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Default SAML access-id for UI login",
				Default:     "use-existing",
			},
			"oidc_access_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Default OIDC access-id for UI login",
				Default:     "use-existing",
			},
			"cert_access_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Default Certificate access-id for UI login",
				Default:     "use-existing",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of the gateway default encryption key",
			},
			"event_on_status_change": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Trigger an event when Gateway status is changed [true/false]",
				Default:     "false",
			},
			"hvp_route_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Hvp route version to use [1/2]",
			},
		},
	}
}

func resourceGatewayUpdateDefaultsRead(d *schema.ResourceData, m interface{}) error {

	rOut, err := getGwDefaultsConfig(m)
	if err != nil {
		return err
	}

	if rOut.SamlAccessId != nil && d.Get("saml_access_id").(string) != common.UseExisting {
		err := d.Set("saml_access_id", *rOut.SamlAccessId)
		if err != nil {
			return err
		}
	}
	if rOut.OidcAccessId != nil && d.Get("oidc_access_id").(string) != common.UseExisting {
		err := d.Set("oidc_access_id", *rOut.OidcAccessId)
		if err != nil {
			return err
		}
	}

	if rOut.CertificateAccessId != nil && d.Get("cert_access_id").(string) != common.UseExisting {
		err := d.Set("cert_access_id", *rOut.CertificateAccessId)
		if err != nil {
			return err
		}
	}
	if rOut.DefaultProtectionKeyId != nil {
		err := d.Set("key", *rOut.DefaultProtectionKeyId)
		if err != nil {
			return err
		}
	}
	if rOut.NotifyOnStatusChange != nil {
		err := d.Set("event_on_status_change", strconv.FormatBool(*rOut.NotifyOnStatusChange))
		if err != nil {
			return err
		}
	}
	if rOut.HvpRouteVersion != nil {
		err := d.Set("hvp_route_version", *rOut.HvpRouteVersion)
		if err != nil {
			return err
		}
	}

	return nil
}

func resourceGatewayUpdateDefaultsUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	samlAccessId := d.Get("saml_access_id").(string)
	oidcAccessId := d.Get("oidc_access_id").(string)
	certAccessId := d.Get("cert_access_id").(string)
	key := d.Get("key").(string)
	eventOnStatusChange := d.Get("event_on_status_change").(string)
	hvpRouteVersion := d.Get("hvp_route_version").(int)

	body := akeyless_api.GatewayUpdateDefaults{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.SamlAccessId, samlAccessId)
	common.GetAkeylessPtr(&body.OidcAccessId, oidcAccessId)
	common.GetAkeylessPtr(&body.CertAccessId, certAccessId)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.EventOnStatusChange, eventOnStatusChange)
	if hvpRouteVersion != 0 {
		body.HvpRouteVersion = akeyless_api.PtrInt64(int64(hvpRouteVersion))
	}

	_, resp, err := client.GatewayUpdateDefaults(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update defaults settings", resp, err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGatewayUpdateDefaultsDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateDefaultsImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	rOut, err := getGwDefaultsConfig(m)
	if err != nil {
		return nil, err
	}

	if rOut.SamlAccessId != nil {
		err := d.Set("saml_access_id", *rOut.SamlAccessId)
		if err != nil {
			return nil, err
		}
	}
	if rOut.OidcAccessId != nil {
		err := d.Set("oidc_access_id", *rOut.OidcAccessId)
		if err != nil {
			return nil, err
		}
	}

	if rOut.CertificateAccessId != nil {
		err := d.Set("cert_access_id", *rOut.CertificateAccessId)
		if err != nil {
			return nil, err
		}
	}
	if rOut.DefaultProtectionKeyId != nil {
		err := d.Set("key", *rOut.DefaultProtectionKeyId)
		if err != nil {
			return nil, err
		}
	}
	if rOut.NotifyOnStatusChange != nil {
		err := d.Set("event_on_status_change", strconv.FormatBool(*rOut.NotifyOnStatusChange))
		if err != nil {
			return nil, err
		}
	}
	if rOut.HvpRouteVersion != nil {
		err := d.Set("hvp_route_version", *rOut.HvpRouteVersion)
		if err != nil {
			return nil, err
		}
	}

	return []*schema.ResourceData{d}, nil
}

func getGwDefaultsConfig(m interface{}) (*akeyless_api.GatewayGetDefaultsOutput, error) {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	body := akeyless_api.GatewayGetDefaults{
		Token: &token,
	}

	rOut, resp, err := client.GatewayGetDefaults(ctx).Body(body).Execute()
	if err != nil {
		return &akeyless_api.GatewayGetDefaultsOutput{}, common.HandleError("can't get defaults settings", resp, err)
	}

	return rOut, nil
}
