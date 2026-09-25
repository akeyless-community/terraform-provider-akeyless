package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRotatedSecretHashiVault() *schema.Resource {
	return &schema.Resource{
		Description: "HashiVault rotated secret resource",
		Create:      resourceRotatedSecretHashiVaultCreate,
		Read:        resourceRotatedSecretHashiVaultRead,
		Update:      resourceRotatedSecretHashiVaultUpdate,
		Delete:      resourceRotatedSecretCommonDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRotatedSecretHashiVaultImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Rotated secret name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that is used to encrypt the secret value (if empty, the account default protectionKey key will be used)",
			},
			"auto_rotate": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to automatically rotate every --rotation-interval days, or disable existing automatic rotation [true/false]",
			},
			"rotation_interval": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The number of days to wait between every automatic key rotation (1-365)",
			},
			"rotation_hour": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The Hour of the rotation in UTC",
			},
			"password_length": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The length of the password to be generated",
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
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
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
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"rotation_event_in": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "How many days before the rotation of the item would you like to be notified",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceRotatedSecretHashiVaultCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	key := d.Get("key").(string)
	autoRotate := d.Get("auto_rotate").(string)
	rotationInterval := d.Get("rotation_interval").(string)
	rotationHour := d.Get("rotation_hour").(int)
	deleteProtection := d.Get("delete_protection").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.RotatedSecretCreateHashiVault{
		Name:       name,
		TargetName: targetName,
		Token:      &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.AutoRotate, autoRotate)
	common.GetAkeylessPtr(&body.RotationInterval, rotationInterval)
	common.GetAkeylessPtr(&body.RotationHour, rotationHour)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	if v, ok := d.GetOk("rotation_event_in"); ok {
		body.RotationEventIn = common.ExpandStringList(v.([]interface{}))
	}

	_, resp, err := client.RotatedSecretCreateHashiVault(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretHashiVaultRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	path := d.Id()

	body := akeyless_api.DescribeItem{
		Name:         path,
		ShowVersions: akeyless_api.PtrBool(true),
		Token:        &token,
	}

	itemOut, res, err := client.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get rotated secret", res, err)
	}

	if itemOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(itemOut.ItemTargetsAssoc)
		if err = common.SetDataByPrefixSlash(d, "target_name", targetName, d.Get("target_name").(string)); err != nil {
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
	if itemOut.AutoRotate != nil {
		if *itemOut.AutoRotate || d.Get("auto_rotate").(string) != "" {
			if err = d.Set("auto_rotate", strconv.FormatBool(*itemOut.AutoRotate)); err != nil {
				return err
			}
		}
	}
	if itemOut.RotationInterval != nil {
		if *itemOut.RotationInterval != 0 || d.Get("rotation_interval").(string) != "" {
			if err = d.Set("rotation_interval", strconv.Itoa(int(*itemOut.RotationInterval))); err != nil {
				return err
			}
		}
	}

	if itemOut.ItemGeneralInfo != nil && itemOut.ItemGeneralInfo.RotatedSecretDetails != nil {
		rsd := itemOut.ItemGeneralInfo.RotatedSecretDetails
		if rsd.RotationHour != nil {
			if err = d.Set("rotation_hour", *rsd.RotationHour); err != nil {
				return err
			}
		}
		if rsd.MaxVersions != nil {
			if err = d.Set("max_versions", strconv.Itoa(int(*rsd.MaxVersions))); err != nil {
				return err
			}
		}
	}

	if itemOut.ItemGeneralInfo != nil && itemOut.ItemGeneralInfo.PasswordPolicy != nil {
		policy := itemOut.ItemGeneralInfo.PasswordPolicy
		if policy.PasswordLength != nil {
			if err = d.Set("password_length", strconv.Itoa(int(*policy.PasswordLength))); err != nil {
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
		if len(customFields) > 0 {
			if err = d.Set("item_custom_fields", customFields); err != nil {
				return err
			}
		}
	}

	if err = setAgenticRulesReadFields(d, itemOut.ItemGeneralInfo.AgenticRules); err != nil {
		return err
	}
	if err = setRotatedSecretPasswordPolicyReadFields(d, itemOut.ItemGeneralInfo); err != nil {
		return err
	}

	d.SetId(path)

	return nil
}

func resourceRotatedSecretHashiVaultUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	key := d.Get("key").(string)
	autoRotate := d.Get("auto_rotate").(string)
	rotationInterval := d.Get("rotation_interval").(string)
	rotationHour := d.Get("rotation_hour").(int)
	deleteProtection := d.Get("delete_protection").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.RotatedSecretUpdateHashiVault{
		Name:    name,
		NewName: akeyless_api.PtrString(name),
		Token:   &token,
	}
	add, remove, err := common.GetTagsForUpdate(d, name, token, tags, client)
	if err == nil {
		if len(add) > 0 {
			common.GetAkeylessPtr(&body.AddTag, add)
		}
		if len(remove) > 0 {
			common.GetAkeylessPtr(&body.RmTag, remove)
		}
	}

	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.AutoRotate, autoRotate)
	common.GetAkeylessPtr(&body.RotationInterval, rotationInterval)
	common.GetAkeylessPtr(&body.RotationHour, rotationHour)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	if v, ok := d.GetOk("rotation_event_in"); ok {
		body.RotationEventIn = common.ExpandStringList(v.([]interface{}))
	}

	_, resp, err := client.RotatedSecretUpdateHashiVault(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretHashiVaultImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()

	err := resourceRotatedSecretHashiVaultRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
