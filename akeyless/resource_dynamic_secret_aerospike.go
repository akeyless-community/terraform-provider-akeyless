// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretAerospike() *schema.Resource {
	return &schema.Resource{
		Description: "Aerospike dynamic secret resource",
		Create:      resourceDynamicSecretAerospikeCreate, Read: resourceDynamicSecretAerospikeRead,
		Update: resourceDynamicSecretAerospikeUpdate, Delete: resourceDynamicSecretAerospikeDelete,
		Importer: &schema.ResourceImporter{State: resourceDynamicSecretAerospikeImport},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Dynamic secret name",
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Target name",
			},
			"aerospike_roles": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Aerospike roles",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "60m",
				Description: "User TTL",
			},
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Temporary username template",
			},
			"password_length": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Generated password length",
			},
			"input_rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Password input rules",
			},
			"output_rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Password output rules",
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
			"skip_dry_run": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Skip dry run",
			},
			"use_capital_letters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Require capital letters",
			},
			"use_lower_letters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Require lower letters",
			},
			"use_numbers": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Require numbers",
			},
			"use_special_characters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Require special characters",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "false",
				Description: "Delete protection",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Custom fields",
			},
		},
	}
}

func resourceDynamicSecretAerospikeCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client, token := *provider.client, *provider.token
	name := d.Get("name").(string)
	roles := common.ExpandStringList(d.Get("aerospike_roles").([]interface{}))
	input, output := common.ExpandStringList(d.Get("input_rule").([]interface{})), common.ExpandStringList(d.Get("output_rule").([]interface{}))
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	passwordLength := d.Get("password_length").(string)
	useCapitalLetters := d.Get("use_capital_letters").(string)
	useLowerLetters := d.Get("use_lower_letters").(string)
	useNumbers := d.Get("use_numbers").(string)
	useSpecialCharacters := d.Get("use_special_characters").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	fields := d.Get("item_custom_fields").(map[string]interface{})
	custom := make(map[string]string, len(fields))
	for k, v := range fields {
		custom[k] = v.(string)
	}
	body := akeyless_api.DynamicSecretCreateAerospike{Name: name, Token: &token, AerospikeRoles: roles, InputRule: input, OutputRule: output}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.UseCapitalLetters, useCapitalLetters)
	common.GetAkeylessPtr(&body.UseLowerLetters, useLowerLetters)
	common.GetAkeylessPtr(&body.UseNumbers, useNumbers)
	common.GetAkeylessPtr(&body.UseSpecialCharacters, useSpecialCharacters)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	rawConfig := d.GetRawConfig()
	if rawConfig.IsKnown() && !rawConfig.IsNull() {
		if raw := rawConfig.GetAttr("ara_enabled"); raw.IsKnown() && !raw.IsNull() {
			common.GetAkeylessPtr(&body.AraEnabled, raw.True())
		}
		if raw := rawConfig.GetAttr("enable_agentic_runtime_authority"); raw.IsKnown() && !raw.IsNull() {
			common.GetAkeylessPtr(&body.EnableAgenticRuntimeAuthority, raw.True())
		}
		if raw := rawConfig.GetAttr("enable_ai_quorum"); raw.IsKnown() && !raw.IsNull() {
			common.GetAkeylessPtr(&body.EnableAiQuorum, raw.True())
		}
		if raw := rawConfig.GetAttr("skip_dry_run"); raw.IsKnown() && !raw.IsNull() {
			common.GetAkeylessPtr(&body.SkipDryRun, raw.True())
		}
	}
	if len(custom) > 0 {
		body.ItemCustomFields = &custom
	}

	_, resp, err := client.DynamicSecretCreateAerospike(context.Background()).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}
	d.SetId(name)
	return nil
}

func resourceDynamicSecretAerospikeUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client, token := *provider.client, *provider.token
	name := d.Get("name").(string)
	roles := common.ExpandStringList(d.Get("aerospike_roles").([]interface{}))
	input, output := common.ExpandStringList(d.Get("input_rule").([]interface{})), common.ExpandStringList(d.Get("output_rule").([]interface{}))
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	passwordLength := d.Get("password_length").(string)
	useCapitalLetters := d.Get("use_capital_letters").(string)
	useLowerLetters := d.Get("use_lower_letters").(string)
	useNumbers := d.Get("use_numbers").(string)
	useSpecialCharacters := d.Get("use_special_characters").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	fields := d.Get("item_custom_fields").(map[string]interface{})
	custom := make(map[string]string, len(fields))
	for k, v := range fields {
		custom[k] = v.(string)
	}
	body := akeyless_api.DynamicSecretUpdateAerospike{Name: name, Token: &token, AerospikeRoles: roles, InputRule: input, OutputRule: output}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.UseCapitalLetters, useCapitalLetters)
	common.GetAkeylessPtr(&body.UseLowerLetters, useLowerLetters)
	common.GetAkeylessPtr(&body.UseNumbers, useNumbers)
	common.GetAkeylessPtr(&body.UseSpecialCharacters, useSpecialCharacters)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	rawConfig := d.GetRawConfig()
	if rawConfig.IsKnown() && !rawConfig.IsNull() {
		if raw := rawConfig.GetAttr("ara_enabled"); raw.IsKnown() && !raw.IsNull() {
			common.GetAkeylessPtr(&body.AraEnabled, raw.True())
		}
		if raw := rawConfig.GetAttr("enable_agentic_runtime_authority"); raw.IsKnown() && !raw.IsNull() {
			common.GetAkeylessPtr(&body.EnableAgenticRuntimeAuthority, raw.True())
		}
		if raw := rawConfig.GetAttr("enable_ai_quorum"); raw.IsKnown() && !raw.IsNull() {
			common.GetAkeylessPtr(&body.EnableAiQuorum, raw.True())
		}
		if raw := rawConfig.GetAttr("skip_dry_run"); raw.IsKnown() && !raw.IsNull() {
			common.GetAkeylessPtr(&body.SkipDryRun, raw.True())
		}
	}
	body.ItemCustomFields = &custom

	_, resp, err := client.DynamicSecretUpdateAerospike(context.Background()).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}
	d.SetId(name)
	return nil
}

func resourceDynamicSecretAerospikeRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	out, resp, err := provider.client.DynamicSecretGet(context.Background()).Body(akeyless_api.DynamicSecretGet{Name: d.Id(), Token: provider.token}).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get dynamic secret value", resp, err)
	}
	if out.UserTtl != nil {
		if err := d.Set("user_ttl", *out.UserTtl); err != nil {
			return err
		}
	}
	if out.DeleteProtection != nil {
		if err := d.Set("delete_protection", strconv.FormatBool(*out.DeleteProtection)); err != nil {
			return err
		}
	}
	if out.SkipDryRun != nil {
		if err := d.Set("skip_dry_run", *out.SkipDryRun); err != nil {
			return err
		}
	}
	if out.ItemTargetsAssoc != nil {
		if err := common.SetDataByPrefixSlash(d, "target_name", common.GetTargetName(out.ItemTargetsAssoc), d.Get("target_name").(string)); err != nil {
			return err
		}
	}
	if out.UsernameTemplate != nil {
		if err := d.Set("custom_username_template", *out.UsernameTemplate); err != nil {
			return err
		}
	}
	if err := d.Set("aerospike_roles", out.AerospikeRoles); err != nil {
		return err
	}
	if out.Metadata != nil {
		if err := d.Set("description", *out.Metadata); err != nil {
			return err
		}
	}
	if out.ItemCustomFieldsDetails != nil {
		customFields := make(map[string]string)
		for _, field := range out.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		if err := d.Set("item_custom_fields", customFields); err != nil {
			return err
		}
	}
	if err := setDynamicSecretPasswordPolicyReadFields(d, out); err != nil {
		return err
	}
	if out.PasswordPolicyInfo != nil {
		if out.PasswordPolicyInfo.UseCapitalLetters != nil {
			if err := d.Set("use_capital_letters", strconv.FormatBool(*out.PasswordPolicyInfo.UseCapitalLetters)); err != nil {
				return err
			}
		}
		if out.PasswordPolicyInfo.UseLowerLetters != nil {
			if err := d.Set("use_lower_letters", strconv.FormatBool(*out.PasswordPolicyInfo.UseLowerLetters)); err != nil {
				return err
			}
		}
		if out.PasswordPolicyInfo.UseNumbers != nil {
			if err := d.Set("use_numbers", strconv.FormatBool(*out.PasswordPolicyInfo.UseNumbers)); err != nil {
				return err
			}
		}
		if out.PasswordPolicyInfo.UseSpecialCharacters != nil {
			if err := d.Set("use_special_characters", strconv.FormatBool(*out.PasswordPolicyInfo.UseSpecialCharacters)); err != nil {
				return err
			}
		}
	}
	if err := setAgenticRulesReadFields(d, out.AgenticRules); err != nil {
		return err
	}
	return nil
}

func resourceDynamicSecretAerospikeDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}
func resourceDynamicSecretAerospikeImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	if err := resourceDynamicSecretAerospikeRead(d, m); err != nil {
		return nil, err
	}
	if err := d.Set("name", d.Id()); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
