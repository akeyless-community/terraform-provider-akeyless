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

func resourceCloudflareTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Cloudflare Target resource",
		Create:      resourceCloudflareTargetCreate,
		Read:        resourceCloudflareTargetRead,
		Update:      resourceCloudflareTargetUpdate,
		Delete:      resourceCloudflareTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceCloudflareTargetImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("api_token"), cty.GetAttrPath("api_token_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"account_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Cloudflare account ID",
			},
			"api_token": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Cloudflare API token",
			},
			"api_token_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"api_token_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "Cloudflare API token (write-only, not stored in state). Requires Terraform 1.11+. Bump api_token_wo_version to change it.",
			},
			"api_token_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"api_token_wo"},
				Description:  "Version trigger for api_token_wo. Increment to update the value.",
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
				Default:     "false",
			},
		},
	}
}

func resourceCloudflareTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	accountID := d.Get("account_id").(string)
	apiToken, err := common.EffectiveSecretValue(d, "api_token", "api_token_wo")
	if err != nil {
		return err
	}
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.TargetCreateCloudflare{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AccountId, accountID)
	common.GetAkeylessPtr(&body.ApiToken, apiToken)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, resp, err := client.TargetCreateCloudflare(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceCloudflareTargetRead(d *schema.ResourceData, m interface{}) error {
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
		return common.HandleReadError(d, "failed to get target details", res, err)
	}

	if rOut.Value != nil && rOut.Value.CloudflareTargetDetails != nil {
		details := rOut.Value.CloudflareTargetDetails
		if details.AccountId != nil {
			if err = d.Set("account_id", *details.AccountId); err != nil {
				return err
			}
		}
		if details.ApiToken != nil {
			if err = common.SetSecretFromRead(d, "api_token", "api_token_wo", "api_token_wo_version", *details.ApiToken); err != nil {
				return err
			}
		}
	}

	if rOut.Target != nil {
		target := rOut.Target
		if target.Comment != nil {
			if err = d.Set("description", *target.Comment); err != nil {
				return err
			}
		}
		if target.DeleteProtection != nil {
			if err = d.Set("delete_protection", strconv.FormatBool(*target.DeleteProtection)); err != nil {
				return err
			}
		}
		if target.ProtectionKeyName != nil {
			if err = d.Set("key", *target.ProtectionKeyName); err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceCloudflareTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	accountID := d.Get("account_id").(string)
	apiToken, err := common.SecretValueForUpdate(d, "api_token", "api_token_wo")
	if err != nil {
		return err
	}
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.TargetUpdateCloudflare{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AccountId, accountID)
	common.SetOptionalString(&body.ApiToken, apiToken)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, resp, err := client.TargetUpdateCloudflare(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceCloudflareTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceCloudflareTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()

	err := resourceCloudflareTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
