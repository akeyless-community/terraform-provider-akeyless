package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRotatedSecretF5BigIp() *schema.Resource {
	return &schema.Resource{
		Description: "F5 BIG-IP rotated secret resource",
		Create:      resourceRotatedSecretF5BigIpCreate,
		Read:        resourceRotatedSecretF5BigIpRead,
		Update:      resourceRotatedSecretF5BigIpUpdate,
		Delete:      resourceRotatedSecretF5BigIpDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRotatedSecretF5BigIpImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Secret name",
				ForceNew:         true,
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"target_name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The target name to associate",
			},
			"rotator_type": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The rotator type [target/password]",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"authentication_credentials": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "use-user-creds",
				Description: "The credentials to connect with [use-user-creds/use-target-creds]",
			},
			"rotated_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "Username to rotate",
			},
			"rotated_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "Password for the username to rotate",
			},
			"auto_rotate": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to automatically rotate the secret",
			},
			"rotation_interval": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Number of days between automatic rotations",
			},
			"rotation_hour": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Hour of the rotation in UTC",
			},
			"password_length": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Length of generated passwords",
			},
			"input_rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Password input rule definitions",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"output_rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Password output rule definitions",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key used to encrypt the secret value",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Tags attached to this secret",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "false",
				Description: "Protection from accidental deletion [true/false]",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Set the maximum number of versions",
			},
			"lock_on_read": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Lock this secret after each successful value read [true/false]",
			},
			"lock_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Lock TTL in minutes",
			},
			"rotate_on_unlock": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Rotate this secret after it is unlocked [true/false]",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep the previous version [true/false]",
			},
			"rotation_event_in": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "How many days before rotation to send a notification",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"skip_dry_run": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Skip the dry run [true/false]",
			},
			"ara_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable Agentic Runtime Authority",
			},
			"enable_agentic_runtime_authority": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable Agentic Runtime Authority",
			},
			"enable_ai_quorum": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable AI Quorum",
			},
			"use_capital_letters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Require an uppercase character in generated passwords",
			},
			"use_lower_letters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Require a lowercase character in generated passwords",
			},
			"use_numbers": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Require a numeric character in generated passwords",
			},
			"use_special_characters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Require a special character in generated passwords",
			},
		},
	}
}

func resourceRotatedSecretF5BigIpCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.RotatedSecretCreateF5BigIp{
		Name:        name,
		TargetName:  d.Get("target_name").(string),
		RotatorType: d.Get("rotator_type").(string),
		Token:       &token,
	}
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.AuthenticationCredentials, d.Get("authentication_credentials").(string))
	common.GetAkeylessPtr(&body.RotatedUsername, d.Get("rotated_username").(string))
	common.GetAkeylessPtr(&body.RotatedPassword, d.Get("rotated_password").(string))
	common.GetAkeylessPtr(&body.AutoRotate, d.Get("auto_rotate").(string))
	common.GetAkeylessPtr(&body.RotationInterval, d.Get("rotation_interval").(string))
	common.GetAkeylessPtr(&body.RotationHour, int32(d.Get("rotation_hour").(int)))
	common.GetAkeylessPtr(&body.PasswordLength, d.Get("password_length").(string))
	common.GetAkeylessPtr(&body.InputRule, common.ExpandStringList(d.Get("input_rule").([]interface{})))
	common.GetAkeylessPtr(&body.OutputRule, common.ExpandStringList(d.Get("output_rule").([]interface{})))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))
	common.GetAkeylessPtr(&body.RotationEventIn, common.ExpandStringList(d.Get("rotation_event_in").([]interface{})))
	common.GetAkeylessPtr(&body.SkipDryRun, d.Get("skip_dry_run").(bool))
	if raw := d.GetRawConfig().GetAttr("ara_enabled"); raw.IsKnown() && !raw.IsNull() {
		common.GetAkeylessPtr(&body.AraEnabled, raw.True())
	}
	if raw := d.GetRawConfig().GetAttr("enable_agentic_runtime_authority"); raw.IsKnown() && !raw.IsNull() {
		common.GetAkeylessPtr(&body.EnableAgenticRuntimeAuthority, raw.True())
	}
	if raw := d.GetRawConfig().GetAttr("enable_ai_quorum"); raw.IsKnown() && !raw.IsNull() {
		common.GetAkeylessPtr(&body.EnableAiQuorum, raw.True())
	}
	common.GetAkeylessPtr(&body.UseCapitalLetters, d.Get("use_capital_letters").(string))
	common.GetAkeylessPtr(&body.UseLowerLetters, d.Get("use_lower_letters").(string))
	common.GetAkeylessPtr(&body.UseNumbers, d.Get("use_numbers").(string))
	common.GetAkeylessPtr(&body.UseSpecialCharacters, d.Get("use_special_characters").(string))
	tags := common.ExpandStringList(d.Get("tags").(*schema.Set).List())
	if len(tags) > 0 {
		body.Tags = tags
	}
	itemCustomFields := common.ExpandStringMap(d.Get("item_custom_fields").(map[string]interface{}))
	if len(itemCustomFields) > 0 {
		body.ItemCustomFields = &itemCustomFields
	}

	_, resp, err := client.RotatedSecretCreateF5BigIp(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create rotated secret", resp, err)
	}
	if keepPrevVersion := d.Get("keep_prev_version").(string); keepPrevVersion != "" {
		updateBody := akeyless_api.RotatedSecretUpdateCustom{Name: name, Token: &token}
		common.GetAkeylessPtr(&updateBody.KeepPrevVersion, keepPrevVersion)
		_, resp, err = client.RotatedSecretUpdateCustom(ctx).Body(updateBody).Execute()
		if err != nil {
			return common.HandleError("can't update rotated secret", resp, err)
		}
	}
	d.SetId(name)
	return nil
}

func resourceRotatedSecretF5BigIpRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	path := d.Id()

	itemOut, _, err := client.DescribeItem(ctx).Body(akeyless_api.DescribeItem{
		Name:         path,
		ShowVersions: akeyless_api.PtrBool(true),
		Token:        &token,
	}).Execute()
	if err != nil {
		return err
	}
	if itemOut.ItemTargetsAssoc != nil {
		if err = common.SetDataByPrefixSlash(d, "target_name", common.GetTargetName(itemOut.ItemTargetsAssoc), d.Get("target_name").(string)); err != nil {
			return err
		}
	}
	if itemOut.ItemMetadata != nil {
		if err = d.Set("description", *itemOut.ItemMetadata); err != nil {
			return err
		}
	}
	if itemOut.ItemTags != nil {
		if err = d.Set("tags", itemOut.ItemTags); err != nil {
			return err
		}
	}
	if itemOut.ProtectionKeyName != nil {
		if err = d.Set("key", *itemOut.ProtectionKeyName); err != nil {
			return err
		}
	}
	if itemOut.DeleteProtection != nil {
		if err = d.Set("delete_protection", strconv.FormatBool(*itemOut.DeleteProtection)); err != nil {
			return err
		}
	}
	if itemOut.AutoRotate != nil {
		if err = d.Set("auto_rotate", strconv.FormatBool(*itemOut.AutoRotate)); err != nil {
			return err
		}
	}
	if itemOut.RotationInterval != nil {
		if err = d.Set("rotation_interval", strconv.Itoa(int(*itemOut.RotationInterval))); err != nil {
			return err
		}
	}
	if itemOut.ItemGeneralInfo != nil && itemOut.ItemGeneralInfo.RotatedSecretDetails != nil {
		details := itemOut.ItemGeneralInfo.RotatedSecretDetails
		if details.RotationHour != nil {
			if err = d.Set("rotation_hour", *details.RotationHour); err != nil {
				return err
			}
		}
		if details.RotatorType != nil {
			if err = d.Set("rotator_type", *details.RotatorType); err != nil {
				return err
			}
		}
		if details.RotatorCredsType != nil {
			if err = d.Set("authentication_credentials", *details.RotatorCredsType); err != nil {
				return err
			}
		}
		if details.MaxVersions != nil {
			if err = d.Set("max_versions", strconv.FormatInt(*details.MaxVersions, 10)); err != nil {
				return err
			}
		}
		if details.SkipDryRun != nil {
			if err = d.Set("skip_dry_run", *details.SkipDryRun); err != nil {
				return err
			}
		}
	}
	if itemOut.ItemGeneralInfo != nil {
		info := itemOut.ItemGeneralInfo
		if info.LockOnRead != nil {
			if err = d.Set("lock_on_read", strconv.FormatBool(*info.LockOnRead)); err != nil {
				return err
			}
		}
		if info.LockTtl != nil {
			if err = d.Set("lock_ttl", strconv.FormatInt(*info.LockTtl, 10)); err != nil {
				return err
			}
		}
		if info.RotateOnUnlock != nil {
			if err = d.Set("rotate_on_unlock", strconv.FormatBool(*info.RotateOnUnlock)); err != nil {
				return err
			}
		} else if info.PendingRotateOnUnlock != nil {
			if err = d.Set("rotate_on_unlock", strconv.FormatBool(*info.PendingRotateOnUnlock)); err != nil {
				return err
			}
		}
		if err = setAgenticRulesReadFields(d, info.AgenticRules); err != nil {
			return err
		}
		if err = setRotatedSecretPasswordPolicyReadFields(d, info); err != nil {
			return err
		}
		if info.NextRotationEvents != nil {
			if err = d.Set("rotation_event_in", common.ReadRotationEventInParam(info.NextRotationEvents)); err != nil {
				return err
			}
		}
	}
	if itemOut.ItemCustomFieldsDetails != nil {
		customFields := make(map[string]string)
		for _, field := range itemOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		if err = d.Set("item_custom_fields", customFields); err != nil {
			return err
		}
	}

	rOut, res, err := client.RotatedSecretGetValue(ctx).Body(akeyless_api.RotatedSecretGetValue{Name: path, Token: &token}).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get rotated secret value", res, err)
	}
	if value, ok := rOut["value"].(map[string]any); ok {
		if username, ok := value["username"].(string); ok {
			if err = d.Set("rotated_username", username); err != nil {
				return err
			}
		}
		if password, ok := value["password"].(string); ok {
			if err = d.Set("rotated_password", password); err != nil {
				return err
			}
		}
	}
	d.SetId(path)
	return nil
}

func resourceRotatedSecretF5BigIpUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.RotatedSecretUpdateCustom{
		Name:  name,
		Token: &token,
	}
	tags := common.ExpandStringList(d.Get("tags").(*schema.Set).List())
	add, remove, err := common.GetTagsForUpdate(d, name, token, tags, client)
	if err != nil {
		return err
	}
	body.AddTag = add
	body.RmTag = remove
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.AuthenticationCredentials, d.Get("authentication_credentials").(string))
	common.GetAkeylessPtr(&body.AutoRotate, d.Get("auto_rotate").(string))
	common.GetAkeylessPtr(&body.RotationInterval, d.Get("rotation_interval").(string))
	common.GetAkeylessPtr(&body.RotationHour, int32(d.Get("rotation_hour").(int)))
	common.GetAkeylessPtr(&body.PasswordLength, d.Get("password_length").(string))
	common.GetAkeylessPtr(&body.InputRule, common.ExpandStringList(d.Get("input_rule").([]interface{})))
	common.GetAkeylessPtr(&body.OutputRule, common.ExpandStringList(d.Get("output_rule").([]interface{})))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))
	common.GetAkeylessPtr(&body.KeepPrevVersion, d.Get("keep_prev_version").(string))
	common.GetAkeylessPtr(&body.RotationEventIn, common.ExpandStringList(d.Get("rotation_event_in").([]interface{})))
	common.GetAkeylessPtr(&body.SkipDryRun, d.Get("skip_dry_run").(bool))
	if raw := d.GetRawConfig().GetAttr("ara_enabled"); raw.IsKnown() && !raw.IsNull() {
		common.GetAkeylessPtr(&body.AraEnabled, raw.True())
	}
	if raw := d.GetRawConfig().GetAttr("enable_agentic_runtime_authority"); raw.IsKnown() && !raw.IsNull() {
		common.GetAkeylessPtr(&body.EnableAgenticRuntimeAuthority, raw.True())
	}
	if raw := d.GetRawConfig().GetAttr("enable_ai_quorum"); raw.IsKnown() && !raw.IsNull() {
		common.GetAkeylessPtr(&body.EnableAiQuorum, raw.True())
	}
	common.GetAkeylessPtr(&body.UseCapitalLetters, d.Get("use_capital_letters").(string))
	common.GetAkeylessPtr(&body.UseLowerLetters, d.Get("use_lower_letters").(string))
	common.GetAkeylessPtr(&body.UseNumbers, d.Get("use_numbers").(string))
	common.GetAkeylessPtr(&body.UseSpecialCharacters, d.Get("use_special_characters").(string))
	itemCustomFields := common.ExpandStringMap(d.Get("item_custom_fields").(map[string]interface{}))
	body.ItemCustomFields = &itemCustomFields

	_, resp, err := client.RotatedSecretUpdateCustom(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update rotated secret", resp, err)
	}
	d.SetId(name)
	return nil
}

func resourceRotatedSecretF5BigIpDelete(d *schema.ResourceData, m interface{}) error {
	return resourceRotatedSecretCommonDelete(d, m)
}

func resourceRotatedSecretF5BigIpImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()
	if err := resourceRotatedSecretF5BigIpRead(d, m); err != nil {
		return nil, err
	}
	if err := d.Set("name", id); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
