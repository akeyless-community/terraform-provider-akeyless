// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRotatedSecretAerospike() *schema.Resource {
	return &schema.Resource{
		Description: "Aerospike rotated secret resource",
		Create:      resourceRotatedSecretAerospikeCreate, Read: resourceRotatedSecretAerospikeRead,
		Update: resourceRotatedSecretAerospikeUpdate, Delete: resourceRotatedSecretAerospikeDelete,
		Importer: &schema.ResourceImporter{State: resourceRotatedSecretAerospikeImport},
		Schema: map[string]*schema.Schema{
			"name":                             {Type: schema.TypeString, Required: true, ForceNew: true, Description: "Rotated secret name"},
			"target_name":                      {Type: schema.TypeString, Required: true, Description: "Target name"},
			"rotator_type":                     {Type: schema.TypeString, Required: true, Description: "Rotator type"},
			"description":                      {Type: schema.TypeString, Optional: true, Description: "Description"},
			"authentication_credentials":       {Type: schema.TypeString, Optional: true, Default: "use-user-creds", Description: "Authentication credentials"},
			"rotated_username":                 {Type: schema.TypeString, Optional: true, Computed: true, Sensitive: true, Description: "Rotated username"},
			"rotated_password":                 {Type: schema.TypeString, Optional: true, Computed: true, Sensitive: true, Description: "Rotated password"},
			"auto_rotate":                      {Type: schema.TypeString, Optional: true, Description: "Automatic rotation"},
			"rotation_interval":                {Type: schema.TypeString, Optional: true, Description: "Rotation interval"},
			"rotation_hour":                    {Type: schema.TypeInt, Optional: true, Description: "Rotation hour"},
			"password_length":                  {Type: schema.TypeString, Optional: true, Description: "Generated password length"},
			"input_rule":                       {Type: schema.TypeList, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Password input rules"},
			"output_rule":                      {Type: schema.TypeList, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Password output rules"},
			"ara_enabled":                      {Type: schema.TypeBool, Optional: true, Description: "Enable Agentic Runtime Authority"},
			"enable_agentic_runtime_authority": {Type: schema.TypeBool, Optional: true, Description: "Enable Agentic Runtime Authority"},
			"enable_ai_quorum":                 {Type: schema.TypeBool, Optional: true, Description: "Enable AI Quorum"},
			"skip_dry_run":                     {Type: schema.TypeBool, Optional: true, Description: "Skip dry run"},
			"key":                              {Type: schema.TypeString, Optional: true, Computed: true, Description: "Protection key"},
			"tags":                             {Type: schema.TypeSet, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Item tags"},
			"delete_protection":                {Type: schema.TypeString, Optional: true, Default: "false", Description: "Delete protection"},
			"item_custom_fields":               {Type: schema.TypeMap, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Custom fields"},
			"max_versions":                     {Type: schema.TypeString, Optional: true, Computed: true, Description: "Maximum versions"},
			"rotation_event_in":                {Type: schema.TypeList, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Rotation notifications"},
			"keep_prev_version":                {Type: schema.TypeString, Optional: true, Description: "Keep previous version"},
			"rotate_on_unlock":                 {Type: schema.TypeString, Optional: true, Description: "Rotate after unlock"},
			"lock_on_read":                     {Type: schema.TypeString, Optional: true, Description: "Lock after read"},
			"lock_ttl":                         {Type: schema.TypeString, Optional: true, Description: "Lock TTL"},
			"use_capital_letters":              {Type: schema.TypeString, Optional: true, Description: "Require capital letters"},
			"use_lower_letters":                {Type: schema.TypeString, Optional: true, Description: "Require lower letters"},
			"use_numbers":                      {Type: schema.TypeString, Optional: true, Description: "Require numbers"},
			"use_special_characters":           {Type: schema.TypeString, Optional: true, Description: "Require special characters"},
		},
	}
}

func resourceRotatedSecretAerospikeWrite(d *schema.ResourceData, m interface{}, update bool) error {
	provider := m.(*providerMeta)
	client, token := *provider.client, *provider.token
	name, target, rotator := d.Get("name").(string), d.Get("target_name").(string), d.Get("rotator_type").(string)
	input, output := common.ExpandStringList(d.Get("input_rule").([]interface{})), common.ExpandStringList(d.Get("output_rule").([]interface{}))
	events := common.ExpandStringList(d.Get("rotation_event_in").([]interface{}))
	tags := common.ExpandStringList(d.Get("tags").(*schema.Set).List())
	fields := d.Get("item_custom_fields").(map[string]interface{})
	custom := make(map[string]string, len(fields))
	for k, v := range fields {
		custom[k] = v.(string)
	}
	set := func(dst interface{}, key string) { common.GetAkeylessPtr(dst, d.Get(key)) }
	if update {
		b := akeyless_api.RotatedSecretUpdateAerospike{Name: name, Token: &token, InputRule: input, OutputRule: output}
		set(&b.AuthenticationCredentials, "authentication_credentials")
		set(&b.AutoRotate, "auto_rotate")
		set(&b.Description, "description")
		set(&b.Key, "key")
		set(&b.RotationInterval, "rotation_interval")
		var hour int32 = int32(d.Get("rotation_hour").(int))
		common.GetAkeylessPtr(&b.RotationHour, hour)
		set(&b.RotatedUsername, "rotated_username")
		set(&b.RotatedPassword, "rotated_password")
		set(&b.PasswordLength, "password_length")
		set(&b.DeleteProtection, "delete_protection")
		set(&b.MaxVersions, "max_versions")
		set(&b.KeepPrevVersion, "keep_prev_version")
		set(&b.RotateOnUnlock, "rotate_on_unlock")
		set(&b.LockOnRead, "lock_on_read")
		set(&b.LockTtl, "lock_ttl")
		set(&b.UseCapitalLetters, "use_capital_letters")
		set(&b.UseLowerLetters, "use_lower_letters")
		set(&b.UseNumbers, "use_numbers")
		set(&b.UseSpecialCharacters, "use_special_characters")
		set(&b.AraEnabled, "ara_enabled")
		set(&b.EnableAgenticRuntimeAuthority, "enable_agentic_runtime_authority")
		set(&b.EnableAiQuorum, "enable_ai_quorum")
		set(&b.SkipDryRun, "skip_dry_run")
		b.RotationEventIn, b.AddTag = events, tags
		b.ItemCustomFields = &custom
		_, resp, err := client.RotatedSecretUpdateAerospike(context.Background()).Body(b).Execute()
		if err != nil {
			return common.HandleError("can't update rotated secret", resp, err)
		}
	} else {
		b := akeyless_api.RotatedSecretCreateAerospike{Name: name, TargetName: target, RotatorType: rotator, Token: &token, InputRule: input, OutputRule: output, Tags: tags, RotationEventIn: events}
		set(&b.AuthenticationCredentials, "authentication_credentials")
		set(&b.AutoRotate, "auto_rotate")
		set(&b.Description, "description")
		set(&b.Key, "key")
		set(&b.RotationInterval, "rotation_interval")
		var hour int32 = int32(d.Get("rotation_hour").(int))
		common.GetAkeylessPtr(&b.RotationHour, hour)
		set(&b.RotatedUsername, "rotated_username")
		set(&b.RotatedPassword, "rotated_password")
		set(&b.PasswordLength, "password_length")
		set(&b.DeleteProtection, "delete_protection")
		set(&b.MaxVersions, "max_versions")
		set(&b.RotateOnUnlock, "rotate_on_unlock")
		set(&b.LockOnRead, "lock_on_read")
		set(&b.LockTtl, "lock_ttl")
		set(&b.UseCapitalLetters, "use_capital_letters")
		set(&b.UseLowerLetters, "use_lower_letters")
		set(&b.UseNumbers, "use_numbers")
		set(&b.UseSpecialCharacters, "use_special_characters")
		set(&b.AraEnabled, "ara_enabled")
		set(&b.EnableAgenticRuntimeAuthority, "enable_agentic_runtime_authority")
		set(&b.EnableAiQuorum, "enable_ai_quorum")
		set(&b.SkipDryRun, "skip_dry_run")
		b.ItemCustomFields = &custom
		_, resp, err := client.RotatedSecretCreateAerospike(context.Background()).Body(b).Execute()
		if err != nil {
			return common.HandleError("can't create rotated secret", resp, err)
		}
		if keepPrevVersion := d.Get("keep_prev_version").(string); keepPrevVersion != "" {
			updateBody := akeyless_api.RotatedSecretUpdateAerospike{Name: name, Token: &token}
			common.GetAkeylessPtr(&updateBody.KeepPrevVersion, keepPrevVersion)
			_, resp, err = client.RotatedSecretUpdateAerospike(context.Background()).Body(updateBody).Execute()
			if err != nil {
				return common.HandleError("can't update rotated secret", resp, err)
			}
		}
	}
	d.SetId(name)
	return nil
}

func resourceRotatedSecretAerospikeCreate(d *schema.ResourceData, m interface{}) error {
	return resourceRotatedSecretAerospikeWrite(d, m, false)
}
func resourceRotatedSecretAerospikeUpdate(d *schema.ResourceData, m interface{}) error {
	return resourceRotatedSecretAerospikeWrite(d, m, true)
}

func resourceRotatedSecretAerospikeRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client, token := *provider.client, *provider.token
	ctx := context.Background()
	path := d.Id()
	itemOut, _, err := client.DescribeItem(ctx).Body(akeyless_api.DescribeItem{Name: path, ShowVersions: akeyless_api.PtrBool(true), Token: &token}).Execute()
	if err != nil {
		return err
	}
	if itemOut.ItemTargetsAssoc != nil {
		if err := common.SetDataByPrefixSlash(d, "target_name", common.GetTargetName(itemOut.ItemTargetsAssoc), d.Get("target_name").(string)); err != nil {
			return err
		}
	}
	if itemOut.ItemMetadata != nil {
		if err := d.Set("description", *itemOut.ItemMetadata); err != nil {
			return err
		}
	}
	if itemOut.ItemTags != nil {
		if err := d.Set("tags", itemOut.ItemTags); err != nil {
			return err
		}
	}
	if itemOut.ProtectionKeyName != nil {
		if err := d.Set("key", *itemOut.ProtectionKeyName); err != nil {
			return err
		}
	}
	if itemOut.DeleteProtection != nil {
		if err := d.Set("delete_protection", strconv.FormatBool(*itemOut.DeleteProtection)); err != nil {
			return err
		}
	}
	if itemOut.AutoRotate != nil {
		if err := d.Set("auto_rotate", strconv.FormatBool(*itemOut.AutoRotate)); err != nil {
			return err
		}
	}
	if itemOut.RotationInterval != nil {
		if err := d.Set("rotation_interval", strconv.Itoa(int(*itemOut.RotationInterval))); err != nil {
			return err
		}
	}
	if itemOut.ItemCustomFieldsDetails != nil {
		customFields := make(map[string]string)
		for _, field := range itemOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		if err := d.Set("item_custom_fields", customFields); err != nil {
			return err
		}
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
		if err := setAgenticRulesReadFields(d, info.AgenticRules); err != nil {
			return err
		}
	}
	if itemOut.ItemGeneralInfo != nil && itemOut.ItemGeneralInfo.RotatedSecretDetails != nil {
		rs := itemOut.ItemGeneralInfo.RotatedSecretDetails
		if rs.RotationHour != nil {
			if err := d.Set("rotation_hour", *rs.RotationHour); err != nil {
				return err
			}
		}
		if rs.RotatorType != nil {
			if err := setRotatorType(d, *rs.RotatorType); err != nil {
				return err
			}
		}
		if rs.RotatorCredsType != nil {
			if err := d.Set("authentication_credentials", *rs.RotatorCredsType); err != nil {
				return err
			}
		}
	}
	if err := setRotatedSecretPasswordPolicyReadFields(d, itemOut.ItemGeneralInfo); err != nil {
		return err
	}
	rOut, res, err := client.RotatedSecretGetValue(ctx).Body(akeyless_api.RotatedSecretGetValue{Name: path, Token: &token}).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get rotated secret value", res, err)
	}
	if value, ok := rOut["value"].(map[string]any); ok {
		if username, ok := value["username"].(string); ok {
			if err := d.Set("rotated_username", username); err != nil {
				return err
			}
		}
		if password, ok := value["password"].(string); ok {
			if err := d.Set("rotated_password", password); err != nil {
				return err
			}
		}
	}
	return nil
}

func resourceRotatedSecretAerospikeDelete(d *schema.ResourceData, m interface{}) error {
	return resourceRotatedSecretCommonDelete(d, m)
}
func resourceRotatedSecretAerospikeImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	if err := resourceRotatedSecretAerospikeRead(d, m); err != nil {
		return nil, err
	}
	if err := d.Set("name", d.Id()); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
