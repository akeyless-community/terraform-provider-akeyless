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

func resourceDynamicSecretSnowflake() *schema.Resource {
	return &schema.Resource{
		Description: "Snowflake dynamic secret resource",
		Create:      resourceDynamicSecretSnowflakeCreate,
		Read:        resourceDynamicSecretSnowflakeRead,
		Update:      resourceDynamicSecretSnowflakeUpdate,
		Delete:      resourceDynamicSecretSnowflakeDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretSnowflakeImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("private_key_passphrase"), cty.GetAttrPath("private_key_passphrase_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("private_key"), cty.GetAttrPath("private_key_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("account_password"), cty.GetAttrPath("account_password_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"account": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Account name",
			},
			"account_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Database Password",
			},
			"account_password_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "account_password (write-only, not stored in state). Requires Terraform 1.11+. Bump account_password_wo_version to change it.",
			},
			"account_password_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for account_password_wo. Increment to update the value.",
			},
			"account_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Database Username",
			},
			"auth_mode": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The authentication mode for the temporary user [password/key]",
				Default:     "password",
			},
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customize how temporary usernames are generated using go template",
			},
			"db_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Database name",
			},
			"key_algo": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Key algorithm",
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
			"private_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "RSA Private key (base64 encoded)",
			},
			"private_key_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "private_key (write-only, not stored in state). Requires Terraform 1.11+. Bump private_key_wo_version to change it.",
			},
			"private_key_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for private_key_wo. Increment to update the value.",
			},
			"private_key_passphrase": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "The Private key passphrase",
			},
			"private_key_passphrase_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "private_key_passphrase (write-only, not stored in state). Requires Terraform 1.11+. Bump private_key_passphrase_wo_version to change it.",
			},
			"private_key_passphrase_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for private_key_passphrase_wo. Increment to update the value.",
			},
			"role": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User role",
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Target name",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "24h",
			},
			"warehouse": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Warehouse name",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceDynamicSecretSnowflakeCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	account := d.Get("account").(string)
	accountPassword, err := common.EffectiveSecretValue(d, "account_password", "account_password_wo")
	if err != nil {
		return err
	}
	accountUsername := d.Get("account_username").(string)
	authMode := d.Get("auth_mode").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	dbName := d.Get("db_name").(string)
	keyAlgo := d.Get("key_algo").(string)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	privateKey, err := common.EffectiveSecretValue(d, "private_key", "private_key_wo")
	if err != nil {
		return err
	}
	privateKeyPassphrase, err := common.EffectiveSecretValue(d, "private_key_passphrase", "private_key_passphrase_wo")
	if err != nil {
		return err
	}
	role := d.Get("role").(string)
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	warehouse := d.Get("warehouse").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.GatewayCreateProducerSnowflake{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.Account, account)
	common.GetAkeylessPtr(&body.AccountPassword, accountPassword)
	common.GetAkeylessPtr(&body.AccountUsername, accountUsername)
	common.GetAkeylessPtr(&body.AuthMode, authMode)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.DbName, dbName)
	common.GetAkeylessPtr(&body.KeyAlgo, keyAlgo)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.PrivateKey, privateKey)
	common.GetAkeylessPtr(&body.PrivateKeyPassphrase, privateKeyPassphrase)
	common.GetAkeylessPtr(&body.Role, role)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Warehouse, warehouse)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.GatewayCreateProducerSnowflake(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretSnowflakeRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get dynamic secret value", res, err)
	}

	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}
	if rOut.Tags != nil {
		err = d.Set("tags", rOut.Tags)
		if err != nil {
			return err
		}
	}

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
		if err != nil {
			return err
		}
	}

	if rOut.UserTtl != nil {
		err = d.Set("user_ttl", *rOut.UserTtl)
		if err != nil {
			return err
		}
	}

	if len(rOut.ItemCustomFieldsDetails) > 0 {
		customFields := make(map[string]string)
		for _, field := range rOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		if len(customFields) > 0 {
			err = d.Set("item_custom_fields", customFields)
			if err != nil {
				return err
			}
		}
	}

	if err = setAgenticRulesReadFields(d, rOut.AgenticRules); err != nil {
		return err
	}
	if err = setDynamicSecretPasswordPolicyReadFields(d, rOut); err != nil {
		return err
	}

	d.SetId(path)

	return nil
}

func resourceDynamicSecretSnowflakeUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	account := d.Get("account").(string)
	accountPassword, err := common.EffectiveSecretValue(d, "account_password", "account_password_wo")
	if err != nil {
		return err
	}
	accountUsername := d.Get("account_username").(string)
	authMode := d.Get("auth_mode").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	dbName := d.Get("db_name").(string)
	keyAlgo := d.Get("key_algo").(string)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	privateKey, err := common.EffectiveSecretValue(d, "private_key", "private_key_wo")
	if err != nil {
		return err
	}
	privateKeyPassphrase, err := common.EffectiveSecretValue(d, "private_key_passphrase", "private_key_passphrase_wo")
	if err != nil {
		return err
	}
	role := d.Get("role").(string)
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	warehouse := d.Get("warehouse").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.GatewayUpdateProducerSnowflake{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.Account, account)
	common.GetAkeylessPtr(&body.AccountPassword, accountPassword)
	common.GetAkeylessPtr(&body.AccountUsername, accountUsername)
	common.GetAkeylessPtr(&body.AuthMode, authMode)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.DbName, dbName)
	common.GetAkeylessPtr(&body.KeyAlgo, keyAlgo)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.PrivateKey, privateKey)
	common.GetAkeylessPtr(&body.PrivateKeyPassphrase, privateKeyPassphrase)
	common.GetAkeylessPtr(&body.Role, role)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Warehouse, warehouse)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.GatewayUpdateProducerSnowflake(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretSnowflakeDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretSnowflakeImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretSnowflakeRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
