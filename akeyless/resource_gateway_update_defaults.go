// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayUpdateDefaults() *schema.Resource {
	return &schema.Resource{
		Description: "Defaults settings",
		Create:      resourceGatewayUpdateDefaultsUpdate,
		Read:        resourceGatewayUpdateDefaultsRead,
		Update:      resourceGatewayUpdateDefaultsUpdate,
		Delete:      resourceGatewayUpdateDefaultsUpdate,
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
				Description: "The name of the gateway default encryption key",
				Default:     "Default",
			},
			"event_on_status_change": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Trigger an event when Gateway status is changed [true/false]",
				Default:     "false",
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

	return nil
}

func resourceGatewayUpdateDefaultsUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	samlAccessId := d.Get("saml_access_id").(string)
	oidcAccessId := d.Get("oidc_access_id").(string)
	certAccessId := d.Get("cert_access_id").(string)
	key := d.Get("key").(string)
	eventOnStatusChange := d.Get("event_on_status_change").(string)

	body := akeyless_api.GatewayUpdateDefaults{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.SamlAccessId, samlAccessId)
	common.GetAkeylessPtr(&body.OidcAccessId, oidcAccessId)
	common.GetAkeylessPtr(&body.CertAccessId, certAccessId)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.EventOnStatusChange, eventOnStatusChange)

	_, _, err := client.GatewayUpdateDefaults(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update defaults settings: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update defaults settings: %v", err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
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

	return []*schema.ResourceData{d}, nil
}

func getGwDefaultsConfig(m interface{}) (akeyless_api.GatewayGetDefaultsOutput, error) {

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	body := akeyless_api.GatewayGetDefaults{
		Token: &token,
	}

	rOut, _, err := client.GatewayGetDefaults(ctx).Body(body).Execute()
	if err != nil {
		var apiErr akeyless_api.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			return akeyless_api.GatewayGetDefaultsOutput{}, fmt.Errorf("can't get defaults settings: %v", string(apiErr.Body()))
		}
		return akeyless_api.GatewayGetDefaultsOutput{}, fmt.Errorf("can't get defaults settings: %w", err)
	}

	return rOut, nil
}
