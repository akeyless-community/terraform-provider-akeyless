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

func resourceBedrockTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Bedrock Target resource",
		Create:      resourceBedrockTargetCreate,
		Read:        resourceBedrockTargetRead,
		Update:      resourceBedrockTargetUpdate,
		Delete:      resourceBedrockTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceBedrockTargetImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("api_key"), cty.GetAttrPath("api_key_wo")),
		},
		Schema: map[string]*schema.Schema{
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
				Description: "API key for Bedrock",
			},
			"api_key_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"api_key_wo_version"},
				WriteOnly:    true,
				Description:  "API key for Bedrock (write-only, not stored in state). Requires Terraform 1.11+. Bump api_key_wo_version to change it.",
			},
			"api_key_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"api_key_wo"},
				Description:  "Version trigger for api_key_wo. Increment to update the value.",
			},
			"bedrock_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base URL of the Bedrock API",
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

func resourceBedrockTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	apiKey, err := common.EffectiveSecretValue(d, "api_key", "api_key_wo")
	if err != nil {
		return err
	}
	bedrockUrl := d.Get("bedrock_url").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.TargetCreateBedrock{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.BedrockUrl, bedrockUrl)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, resp, err := client.TargetCreateBedrock(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)
	return nil
}

func resourceBedrockTargetRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.Value != nil && rOut.Value.BedrockTargetDetails != nil {
		if rOut.Value.BedrockTargetDetails.ApiKey != nil {
			if err = common.SetSecretFromRead(d, "api_key", "api_key_wo", "api_key_wo_version", *rOut.Value.BedrockTargetDetails.ApiKey); err != nil {
				return err
			}
		}
		if rOut.Value.BedrockTargetDetails.BedrockUrl != nil {
			if err = d.Set("bedrock_url", *rOut.Value.BedrockTargetDetails.BedrockUrl); err != nil {
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

func resourceBedrockTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()

	name := d.Get("name").(string)
	apiKey, err := common.SecretValueForUpdate(d, "api_key", "api_key_wo")
	if err != nil {
		return err
	}
	bedrockUrl := d.Get("bedrock_url").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	deleteProtection := d.Get("delete_protection").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.TargetUpdateBedrock{Name: name, Token: &token}
	common.SetOptionalString(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.BedrockUrl, bedrockUrl)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.TargetUpdateBedrock(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}
	d.SetId(name)
	return nil
}

func resourceBedrockTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	path := d.Id()
	ctx := context.Background()
	_, _, err := client.TargetDelete(ctx).Body(akeyless_api.TargetDelete{Token: &token, Name: path}).Execute()
	return err
}

func resourceBedrockTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()
	if err := resourceBedrockTargetRead(d, m); err != nil {
		return nil, err
	}
	if err := d.Set("name", id); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
