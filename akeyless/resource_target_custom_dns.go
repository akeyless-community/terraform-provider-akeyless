// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceCustomDnsTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Custom DNS Target resource",
		Create:      resourceCustomDnsTargetCreate,
		Read:        resourceCustomDnsTargetRead,
		Update:      resourceCustomDnsTargetUpdate,
		Delete:      resourceCustomDnsTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceCustomDnsTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Target name",
				ForceNew:         true,
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"provider_type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "DNS provider type",
			},
			"dns_parameter": {
				Type:        schema.TypeMap,
				Required:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "DNS provider parameters",
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

func expandStringMap(raw map[string]interface{}) map[string]string {
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		out[k] = v.(string)
	}
	return out
}

func resourceCustomDnsTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.TargetCreateCustomDns{
		Name:         name,
		Token:        &token,
		ProviderType: d.Get("provider_type").(string),
		DnsParameter: expandStringMap(d.Get("dns_parameter").(map[string]interface{})),
	}
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))

	_, resp, err := client.TargetCreateCustomDns(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}
	d.SetId(name)
	return nil
}

func resourceCustomDnsTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	path := d.Id()

	rOut, res, err := client.TargetGetDetails(ctx).Body(akeyless_api.TargetGetDetails{Name: path, Token: &token}).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get target details", res, err)
	}
	if rOut.Value != nil && rOut.Value.CustomDnsTargetDetails != nil {
		details := rOut.Value.CustomDnsTargetDetails
		if details.ProviderType != nil {
			if err = d.Set("provider_type", *details.ProviderType); err != nil {
				return err
			}
		}
		if details.Parameters != nil {
			if err = d.Set("dns_parameter", *details.Parameters); err != nil {
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

func resourceCustomDnsTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.TargetUpdateCustomDns{
		Name:         name,
		Token:        &token,
		ProviderType: d.Get("provider_type").(string),
		DnsParameter: expandStringMap(d.Get("dns_parameter").(map[string]interface{})),
	}
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&body.KeepPrevVersion, d.Get("keep_prev_version").(string))

	_, resp, err := client.TargetUpdateCustomDns(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}
	d.SetId(name)
	return nil
}

func resourceCustomDnsTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	_, _, err := client.TargetDelete(context.Background()).Body(akeyless_api.TargetDelete{Token: &token, Name: d.Id()}).Execute()
	return err
}

func resourceCustomDnsTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()
	if err := resourceCustomDnsTargetRead(d, m); err != nil {
		return nil, err
	}
	if err := d.Set("name", id); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
