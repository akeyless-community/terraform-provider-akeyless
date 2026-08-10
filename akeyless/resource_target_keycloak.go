// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceKeycloakTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Keycloak Target resource",
		Create:      resourceKeycloakTargetCreate,
		Read:        resourceKeycloakTargetRead,
		Update:      resourceKeycloakTargetUpdate,
		Delete:      resourceKeycloakTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceKeycloakTargetImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("client_secret"), cty.GetAttrPath("client_secret_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Target name",
				ForceNew:         true,
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Keycloak URL",
			},
			"realm": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Keycloak realm",
			},
			"client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Keycloak client ID",
			},
			"client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Keycloak client secret",
			},
			"client_secret_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"client_secret_wo_version"},
				WriteOnly:    true,
				Description:  "Keycloak client secret (write-only, not stored in state). Requires Terraform 1.11+. Bump client_secret_wo_version to change it.",
			},
			"client_secret_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"client_secret_wo"},
				Description:  "Version trigger for client_secret_wo. Increment to update the secret.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that used to encrypt the target secret value (if empty, the account default protectionKey key will be used)",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "false",
				Description: "Protection from accidental deletion of this object [true/false]",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceKeycloakTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)
	clientSecret, err := common.EffectiveSecretValue(d, "client_secret", "client_secret_wo")
	if err != nil {
		return err
	}

	body := akeyless_api.TargetCreateKeycloak{Name: name, Token: &token}
	common.GetAkeylessPtr(&body.Url, d.Get("url").(string))
	common.GetAkeylessPtr(&body.Realm, d.Get("realm").(string))
	common.GetAkeylessPtr(&body.ClientId, d.Get("client_id").(string))
	common.GetAkeylessPtr(&body.ClientSecret, clientSecret)
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))

	_, resp, err := client.TargetCreateKeycloak(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}
	d.SetId(name)
	return nil
}

func resourceKeycloakTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	path := d.Id()

	rOut, res, err := client.TargetGetDetails(ctx).Body(akeyless_api.TargetGetDetails{Name: path, Token: &token}).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get target details", res, err)
	}
	if rOut.Value != nil && rOut.Value.KeycloakTargetDetails != nil {
		details := rOut.Value.KeycloakTargetDetails
		if details.KeycloakUrl != nil {
			if err = d.Set("url", *details.KeycloakUrl); err != nil {
				return err
			}
		}
		if details.KeycloakRealm != nil {
			if err = d.Set("realm", *details.KeycloakRealm); err != nil {
				return err
			}
		}
		if details.KeycloakClientId != nil {
			if err = d.Set("client_id", *details.KeycloakClientId); err != nil {
				return err
			}
		}
		if details.KeycloakClientSecret != nil {
			if err = common.SetSecretFromRead(d, "client_secret", "client_secret_wo", "client_secret_wo_version", *details.KeycloakClientSecret); err != nil {
				return err
			}
		}
	}
	if rOut.Target != nil {
		if rOut.Target.Comment != nil {
			if err = d.Set("description", *rOut.Target.Comment); err != nil {
				return err
			}
		}
		if rOut.Target.ProtectionKeyName != nil {
			if err = d.Set("key", *rOut.Target.ProtectionKeyName); err != nil {
				return err
			}
		}
		if rOut.Target.DeleteProtection != nil {
			if err = d.Set("delete_protection", strconv.FormatBool(*rOut.Target.DeleteProtection)); err != nil {
				return err
			}
		}
	}
	d.SetId(path)
	return nil
}

func resourceKeycloakTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)
	clientSecret, err := common.SecretValueForUpdate(d, "client_secret", "client_secret_wo")
	if err != nil {
		return err
	}

	body := akeyless_api.TargetUpdateKeycloak{Name: name, Token: &token}
	common.GetAkeylessPtr(&body.Url, d.Get("url").(string))
	common.GetAkeylessPtr(&body.Realm, d.Get("realm").(string))
	common.GetAkeylessPtr(&body.ClientId, d.Get("client_id").(string))
	common.SetOptionalString(&body.ClientSecret, clientSecret)
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&body.KeepPrevVersion, d.Get("keep_prev_version").(string))

	_, resp, err := client.TargetUpdateKeycloak(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}
	d.SetId(name)
	return nil
}

func resourceKeycloakTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	_, _, err := client.TargetDelete(context.Background()).Body(akeyless_api.TargetDelete{Token: &token, Name: d.Id()}).Execute()
	return err
}

func resourceKeycloakTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()
	if err := resourceKeycloakTargetRead(d, m); err != nil {
		return nil, err
	}
	if err := d.Set("name", id); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
