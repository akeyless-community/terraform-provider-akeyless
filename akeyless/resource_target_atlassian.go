package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAtlassianTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Atlassian Target resource",
		Create:      resourceAtlassianTargetCreate,
		Read:        resourceAtlassianTargetRead,
		Update:      resourceAtlassianTargetUpdate,
		Delete:      resourceAtlassianTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAtlassianTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Target name",
				ForceNew:         true,
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"atlassian_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Atlassian site base URL (https://<site>.atlassian.net, or a Data Center base URL)",
			},
			"atlassian_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Atlassian account email paired with a Cloud API token (not needed for a Data Center personal access token)",
			},
			"atlassian_token": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Atlassian Cloud API token, or Data Center personal access token",
			},
			"atlassian_automation_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Optional Automation REST API key (Jira settings > System > Automation > API keys) so the scan can read the automation rules; without it they are reported as not read",
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
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used.",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults",
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

func resourceAtlassianTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.TargetCreateAtlassian{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AtlassianUrl, d.Get("atlassian_url").(string))
	common.GetAkeylessPtr(&body.AtlassianEmail, d.Get("atlassian_email").(string))
	common.GetAkeylessPtr(&body.AtlassianToken, d.Get("atlassian_token").(string))
	common.GetAkeylessPtr(&body.AtlassianAutomationKey, d.Get("atlassian_automation_key").(string))
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))

	_, resp, err := client.TargetCreateAtlassian(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceAtlassianTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get target details", res, err)
	}

	if rOut.Value != nil && rOut.Value.AtlassianTargetDetails != nil {
		details := rOut.Value.AtlassianTargetDetails
		if details.AtlassianUrl != nil {
			if err = d.Set("atlassian_url", *details.AtlassianUrl); err != nil {
				return err
			}
		}
		if details.AtlassianEmail != nil {
			if err = d.Set("atlassian_email", *details.AtlassianEmail); err != nil {
				return err
			}
		}
		if details.AtlassianToken != nil {
			if err = d.Set("atlassian_token", *details.AtlassianToken); err != nil {
				return err
			}
		}
		if details.AtlassianAutomationKey != nil {
			if err = d.Set("atlassian_automation_key", *details.AtlassianAutomationKey); err != nil {
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

func resourceAtlassianTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.TargetUpdateAtlassian{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AtlassianUrl, d.Get("atlassian_url").(string))
	common.GetAkeylessPtr(&body.AtlassianEmail, d.Get("atlassian_email").(string))
	common.GetAkeylessPtr(&body.AtlassianToken, d.Get("atlassian_token").(string))
	common.GetAkeylessPtr(&body.AtlassianAutomationKey, d.Get("atlassian_automation_key").(string))
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&body.KeepPrevVersion, d.Get("keep_prev_version").(string))

	_, resp, err := client.TargetUpdateAtlassian(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceAtlassianTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.TargetDelete{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.TargetDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceAtlassianTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	path := d.Id()

	err := resourceAtlassianTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
