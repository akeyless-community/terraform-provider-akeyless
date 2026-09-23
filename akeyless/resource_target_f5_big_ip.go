package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceF5BigIpTarget() *schema.Resource {
	return &schema.Resource{
		Description: "F5 BIG-IP Target resource",
		Create:      resourceF5BigIpTargetCreate,
		Read:        resourceF5BigIpTargetRead,
		Update:      resourceF5BigIpTargetUpdate,
		Delete:      resourceF5BigIpTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceF5BigIpTargetImport,
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
				Required:    true,
				Description: "F5 BIG-IP management URL",
			},
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "F5 username with permission to manage certificates",
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "F5 password",
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
				Description: "The name of a key used to encrypt the target secret value",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by account settings",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "false",
				Description: "Protection from accidental deletion of this object [true/false]",
			},
			"lock_on_read": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Lock this target after each successful value read [true/false]",
			},
			"lock_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Lock TTL in minutes",
			},
			"rotate_on_unlock": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Rotate this target after it is unlocked [true/false]",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep the previous version [true/false]",
			},
		},
	}
}

func resourceF5BigIpTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.TargetCreateF5BigIp{
		Name:     name,
		Url:      d.Get("url").(string),
		Username: d.Get("username").(string),
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.Password, d.Get("password").(string))
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))

	_, resp, err := client.TargetCreateF5BigIp(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}
	if keepPrevVersion := d.Get("keep_prev_version").(string); keepPrevVersion != "" {
		updateBody := akeyless_api.TargetUpdateF5BigIp{Name: name, Token: &token}
		common.GetAkeylessPtr(&updateBody.KeepPrevVersion, keepPrevVersion)
		_, resp, err = client.TargetUpdateF5BigIp(ctx).Body(updateBody).Execute()
		if err != nil {
			return common.HandleError("can't update target", resp, err)
		}
	}
	d.SetId(name)
	return nil
}

func resourceF5BigIpTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	path := d.Id()

	body := akeyless_api.TargetGetDetails{Name: path, Token: &token}
	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get target details", res, err)
	}

	if rOut.Value != nil && rOut.Value.F5BigIpTargetDetails != nil {
		details := rOut.Value.F5BigIpTargetDetails
		if details.Url != nil {
			if err = d.Set("url", *details.Url); err != nil {
				return err
			}
		}
		if details.Username != nil {
			if err = d.Set("username", *details.Username); err != nil {
				return err
			}
		}
		if details.Password != nil {
			if err = d.Set("password", *details.Password); err != nil {
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

func resourceF5BigIpTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.TargetUpdateF5BigIp{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Url, d.Get("url").(string))
	common.GetAkeylessPtr(&body.Username, d.Get("username").(string))
	common.GetAkeylessPtr(&body.Password, d.Get("password").(string))
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))
	common.GetAkeylessPtr(&body.KeepPrevVersion, d.Get("keep_prev_version").(string))

	_, resp, err := client.TargetUpdateF5BigIp(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}
	d.SetId(name)
	return nil
}

func resourceF5BigIpTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	body := akeyless_api.TargetDelete{Name: d.Id(), Token: &token}
	_, _, err := client.TargetDelete(context.Background()).Body(body).Execute()
	return err
}

func resourceF5BigIpTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()
	if err := resourceF5BigIpTargetRead(d, m); err != nil {
		return nil, err
	}
	if err := d.Set("name", id); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
