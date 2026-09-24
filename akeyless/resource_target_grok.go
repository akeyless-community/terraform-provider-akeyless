// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGrokTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Grok Target resource",
		Create:      resourceGrokTargetCreate,
		Read:        resourceGrokTargetRead,
		Update:      resourceGrokTargetUpdate,
		Delete:      resourceGrokTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGrokTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"lock_on_read":     {Type: schema.TypeString, Optional: true, Description: "Lock after read"},
			"lock_ttl":         {Type: schema.TypeString, Optional: true, Description: "Lock TTL in minutes"},
			"rotate_on_unlock": {Type: schema.TypeString, Optional: true, Description: "Rotate after unlock"},

			"name": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Target name",
				ForceNew:         true,
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "API key for Grok",
			},
			"grok_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base URL of the Grok API",
			},
			"team_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Team ID",
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

func resourceGrokTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.TargetCreateGrok{Name: name, Token: &token}
	common.GetAkeylessPtr(&body.ApiKey, d.Get("api_key").(string))
	common.GetAkeylessPtr(&body.GrokUrl, d.Get("grok_url").(string))
	common.GetAkeylessPtr(&body.TeamId, d.Get("team_id").(string))
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))

	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))

	_, resp, err := client.TargetCreateGrok(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}
	d.SetId(name)
	return nil
}

func resourceGrokTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	path := d.Id()

	rOut, res, err := client.TargetGetDetails(ctx).Body(akeyless_api.TargetGetDetails{Name: path, Token: &token}).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get target details", res, err)
	}
	if rOut.Value != nil && rOut.Value.GrokTargetDetails != nil {
		if rOut.Value.GrokTargetDetails.ApiKey != nil {
			if err = d.Set("api_key", *rOut.Value.GrokTargetDetails.ApiKey); err != nil {
				return err
			}
		}
		if rOut.Value.GrokTargetDetails.GrokUrl != nil {
			if err = d.Set("grok_url", *rOut.Value.GrokTargetDetails.GrokUrl); err != nil {
				return err
			}
		}
		if rOut.Value.GrokTargetDetails.TeamId != nil {
			if err = d.Set("team_id", *rOut.Value.GrokTargetDetails.TeamId); err != nil {
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

	itemOut, _, err := client.DescribeItem(ctx).Body(akeyless_api.DescribeItem{Name: path, Token: &token}).Execute()
	if err != nil {
		return err
	}
	if itemOut.ItemGeneralInfo != nil {
		info := itemOut.ItemGeneralInfo
		if info.LockOnRead != nil {
			if err := d.Set("lock_on_read", strconv.FormatBool(*info.LockOnRead)); err != nil {
				return err
			}
		}
		if info.LockTtl != nil {
			if err := d.Set("lock_ttl", strconv.FormatInt(*info.LockTtl, 10)); err != nil {
				return err
			}
		}
		if info.RotateOnUnlock != nil {
			if err := d.Set("rotate_on_unlock", strconv.FormatBool(*info.RotateOnUnlock)); err != nil {
				return err
			}
		} else if info.PendingRotateOnUnlock != nil {
			if err := d.Set("rotate_on_unlock", strconv.FormatBool(*info.PendingRotateOnUnlock)); err != nil {
				return err
			}
		}
	}

	d.SetId(path)
	return nil
}

func resourceGrokTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.TargetUpdateGrok{Name: name, Token: &token}
	common.GetAkeylessPtr(&body.ApiKey, d.Get("api_key").(string))
	common.GetAkeylessPtr(&body.GrokUrl, d.Get("grok_url").(string))
	common.GetAkeylessPtr(&body.TeamId, d.Get("team_id").(string))
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&body.KeepPrevVersion, d.Get("keep_prev_version").(string))

	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))

	_, resp, err := client.TargetUpdateGrok(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}
	d.SetId(name)
	return nil
}

func resourceGrokTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	_, _, err := client.TargetDelete(context.Background()).Body(akeyless_api.TargetDelete{Token: &token, Name: d.Id()}).Execute()
	return err
}

func resourceGrokTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()
	if err := resourceGrokTargetRead(d, m); err != nil {
		return nil, err
	}
	if err := d.Set("name", id); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
