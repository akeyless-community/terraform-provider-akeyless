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
			"name":                             {Type: schema.TypeString, Required: true, ForceNew: true, Description: "Dynamic secret name"},
			"target_name":                      {Type: schema.TypeString, Optional: true, Description: "Target name"},
			"aerospike_roles":                  {Type: schema.TypeList, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Aerospike roles"},
			"user_ttl":                         {Type: schema.TypeString, Optional: true, Default: "60m", Description: "User TTL"},
			"custom_username_template":         {Type: schema.TypeString, Optional: true, Description: "Temporary username template"},
			"password_length":                  {Type: schema.TypeString, Optional: true, Description: "Generated password length"},
			"input_rule":                       {Type: schema.TypeList, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Password input rules"},
			"output_rule":                      {Type: schema.TypeList, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Password output rules"},
			"ara_enabled":                      {Type: schema.TypeBool, Optional: true, Description: "Enable Agentic Runtime Authority"},
			"enable_agentic_runtime_authority": {Type: schema.TypeBool, Optional: true, Description: "Enable Agentic Runtime Authority"},
			"enable_ai_quorum":                 {Type: schema.TypeBool, Optional: true, Description: "Enable AI Quorum"},
			"skip_dry_run":                     {Type: schema.TypeBool, Optional: true, Description: "Skip dry run"},
			"use_capital_letters":              {Type: schema.TypeString, Optional: true, Description: "Require capital letters"},
			"use_lower_letters":                {Type: schema.TypeString, Optional: true, Description: "Require lower letters"},
			"use_numbers":                      {Type: schema.TypeString, Optional: true, Description: "Require numbers"},
			"use_special_characters":           {Type: schema.TypeString, Optional: true, Description: "Require special characters"},
			"delete_protection":                {Type: schema.TypeString, Optional: true, Default: "false", Description: "Delete protection"},
			"description":                      {Type: schema.TypeString, Optional: true, Description: "Description"},
			"item_custom_fields":               {Type: schema.TypeMap, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}, Description: "Custom fields"},
		},
	}
}

func resourceDynamicSecretAerospikeWrite(d *schema.ResourceData, m interface{}, update bool) error {
	provider := m.(*providerMeta)
	client, token := *provider.client, *provider.token
	name := d.Get("name").(string)
	roles := common.ExpandStringList(d.Get("aerospike_roles").([]interface{}))
	input, output := common.ExpandStringList(d.Get("input_rule").([]interface{})), common.ExpandStringList(d.Get("output_rule").([]interface{}))
	fields := d.Get("item_custom_fields").(map[string]interface{})
	custom := make(map[string]string, len(fields))
	for k, v := range fields {
		custom[k] = v.(string)
	}
	set := func(dst interface{}, key string) { common.GetAkeylessPtr(dst, d.Get(key)) }
	if update {
		b := akeyless_api.DynamicSecretUpdateAerospike{Name: name, Token: &token, AerospikeRoles: roles, InputRule: input, OutputRule: output}
		set(&b.TargetName, "target_name")
		set(&b.UserTtl, "user_ttl")
		set(&b.CustomUsernameTemplate, "custom_username_template")
		set(&b.PasswordLength, "password_length")
		set(&b.UseCapitalLetters, "use_capital_letters")
		set(&b.UseLowerLetters, "use_lower_letters")
		set(&b.UseNumbers, "use_numbers")
		set(&b.UseSpecialCharacters, "use_special_characters")
		set(&b.AraEnabled, "ara_enabled")
		set(&b.EnableAgenticRuntimeAuthority, "enable_agentic_runtime_authority")
		set(&b.EnableAiQuorum, "enable_ai_quorum")
		set(&b.SkipDryRun, "skip_dry_run")
		set(&b.DeleteProtection, "delete_protection")
		set(&b.Description, "description")
		b.ItemCustomFields = &custom
		_, resp, err := client.DynamicSecretUpdateAerospike(context.Background()).Body(b).Execute()
		if err != nil {
			return common.HandleError("can't update dynamic secret", resp, err)
		}
	} else {
		b := akeyless_api.DynamicSecretCreateAerospike{Name: name, Token: &token, AerospikeRoles: roles, InputRule: input, OutputRule: output}
		set(&b.TargetName, "target_name")
		set(&b.UserTtl, "user_ttl")
		set(&b.CustomUsernameTemplate, "custom_username_template")
		set(&b.PasswordLength, "password_length")
		set(&b.UseCapitalLetters, "use_capital_letters")
		set(&b.UseLowerLetters, "use_lower_letters")
		set(&b.UseNumbers, "use_numbers")
		set(&b.UseSpecialCharacters, "use_special_characters")
		set(&b.AraEnabled, "ara_enabled")
		set(&b.EnableAgenticRuntimeAuthority, "enable_agentic_runtime_authority")
		set(&b.EnableAiQuorum, "enable_ai_quorum")
		set(&b.SkipDryRun, "skip_dry_run")
		set(&b.DeleteProtection, "delete_protection")
		set(&b.Description, "description")
		if len(custom) > 0 {
			b.ItemCustomFields = &custom
		}
		_, resp, err := client.DynamicSecretCreateAerospike(context.Background()).Body(b).Execute()
		if err != nil {
			return common.HandleError("can't create dynamic secret", resp, err)
		}
	}
	d.SetId(name)
	return nil
}

func resourceDynamicSecretAerospikeCreate(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretAerospikeWrite(d, m, false)
}
func resourceDynamicSecretAerospikeUpdate(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretAerospikeWrite(d, m, true)
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
	if len(out.AerospikeRoles) > 0 {
		if err := d.Set("aerospike_roles", out.AerospikeRoles); err != nil {
			return err
		}
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
	if err := setAgenticRulesReadFields(d, out.AgenticRules); err != nil {
		return err
	}
	if err := setDynamicSecretSkipDryRunReadField(d, out.SkipDryRun); err != nil {
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
