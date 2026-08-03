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

func resourceDynamicSecretMssql() *schema.Resource {
	return &schema.Resource{
		Description: "Microsoft SQL Server dynamic secret resource",
		Create:      resourceDynamicSecretMssqlCreate,
		Read:        resourceDynamicSecretMssqlRead,
		Update:      resourceDynamicSecretMssqlUpdate,
		Delete:      resourceDynamicSecretMssqlDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretMssqlImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("mssql_password"), cty.GetAttrPath("mssql_password_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of existing target to use in dynamic secret creation",
			},
			"mssql_dbname": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MSSQL Name",
			},
			"mssql_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MSSQL Username",
			},
			"mssql_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "MSSQL Password",
			},
			"mssql_password_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "MSSQL Password (write-only, not stored in state). Requires Terraform 1.11+. Bump mssql_password_wo_version to change it.",
			},
			"mssql_password_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for mssql_password_wo. Increment to update the value.",
			},
			"mssql_host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MSSQL Host",
				Default:     "127.0.0.1",
			},
			"mssql_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MSSQL Port",
				Default:     "1433",
			},
			"mssql_create_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MSSQL Creation statements",
				Default:     `CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';`,
			},
			"mssql_revocation_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MSSQL Revocation statements",
				Default:     `DROP LOGIN [{{name}}];`,
			},
			"mssql_allowed_db_names": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "CSV of allowed DB names for runtime selection when getting the secret value. Empty => use target DB only; \"*\" => any DB allowed; One or more names => user must choose from this list",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
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
			"encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Encrypt dynamic secret details with following key",
			},
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customize how temporary usernames are generated using go template",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_certificate_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Secure Access",
			},
			"secure_access_bastion_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Bastion",
				Deprecated:  "use secure_access_certificate_issuer instead",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Target DB servers for connections (In case of Linked Target association, host(s) will inherit Linked Target hosts)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_db_schema": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The db schema",
			},
			"secure_access_delay": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The delay duration, in seconds, to wait after generating just-in-time credentials. Accepted range: 0-120 seconds",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable Web Secure Remote Access",
			},
			"secure_access_db_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The DB Name",
			},
		},
	}
}

func resourceDynamicSecretMssqlCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	mssqlDbname := d.Get("mssql_dbname").(string)
	mssqlUsername := d.Get("mssql_username").(string)
	mssqlPassword, err := common.EffectiveSecretValue(d, "mssql_password", "mssql_password_wo")
	if err != nil {
		return err
	}
	mssqlHost := d.Get("mssql_host").(string)
	mssqlPort := d.Get("mssql_port").(string)
	mssqlCreateStatements := d.Get("mssql_create_statements").(string)
	mssqlRevocationStatements := d.Get("mssql_revocation_statements").(string)
	mssqlAllowedDbNames := d.Get("mssql_allowed_db_names").(string)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	if secureAccessCertificateIssuer == "" {
		secureAccessCertificateIssuer = d.Get("secure_access_bastion_issuer").(string)
	}
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessDbSchema := d.Get("secure_access_db_schema").(string)
	secureAccessDelay := d.Get("secure_access_delay").(int)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.DynamicSecretCreateMsSql{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.MssqlDbname, mssqlDbname)
	common.GetAkeylessPtr(&body.MssqlUsername, mssqlUsername)
	common.GetAkeylessPtr(&body.MssqlPassword, mssqlPassword)
	common.GetAkeylessPtr(&body.MssqlHost, mssqlHost)
	common.GetAkeylessPtr(&body.MssqlPort, mssqlPort)
	common.GetAkeylessPtr(&body.MssqlCreateStatements, mssqlCreateStatements)
	common.GetAkeylessPtr(&body.MssqlRevocationStatements, mssqlRevocationStatements)
	common.GetAkeylessPtr(&body.MssqlAllowedDbNames, mssqlAllowedDbNames)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		body.ItemCustomFields = &itemCustomFields
	}
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessDbSchema, secureAccessDbSchema)
	common.GetAkeylessPtr(&body.SecureAccessDelay, secureAccessDelay)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, resp, err := client.DynamicSecretCreateMsSql(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretMssqlRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.MssqlRevocationStatements != nil {
		err = d.Set("mssql_revocation_statements", *rOut.MssqlRevocationStatements)
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
	if rOut.Tags != nil {
		err = d.Set("tags", rOut.Tags)
		if err != nil {
			return err
		}
	}

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = common.SetDataByPrefixSlash(d, "target_name", targetName, d.Get("target_name").(string))
		if err != nil {
			return err
		}
	}
	if rOut.DbName != nil {
		err = d.Set("mssql_dbname", *rOut.DbName)
		if err != nil {
			return err
		}
	}
	if rOut.DbUserName != nil {
		err = d.Set("mssql_username", *rOut.DbUserName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPwd != nil {
		err = common.SetSecretFromRead(d, "mssql_password", "mssql_password_wo", "mssql_password_wo_version", *rOut.DbPwd)
		if err != nil {
			return err
		}
	}
	if rOut.DbHostName != nil {
		err = d.Set("mssql_host", *rOut.DbHostName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPort != nil {
		err = d.Set("mssql_port", *rOut.DbPort)
		if err != nil {
			return err
		}
	}
	if rOut.MssqlCreationStatements != nil {
		err = d.Set("mssql_create_statements", *rOut.MssqlCreationStatements)
		if err != nil {
			return err
		}
	}
	if rOut.DynamicSecretKey != nil {
		err = common.SetDataByPrefixSlash(d, "encryption_key_name", *rOut.DynamicSecretKey, d.Get("encryption_key_name").(string))
		if err != nil {
			return err
		}
	}

	if rOut.UsernameTemplate != nil {
		err = d.Set("custom_username_template", *rOut.UsernameTemplate)
		if err != nil {
			return err
		}
	}
	if rOut.MssqlAllowedDbNames != nil {
		err = d.Set("mssql_allowed_db_names", *rOut.MssqlAllowedDbNames)
		if err != nil {
			return err
		}
	}
	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}
	if rOut.Metadata != nil {
		err = d.Set("description", *rOut.Metadata)
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

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	if err = setAgenticRulesReadFields(d, rOut.AgenticRules); err != nil {
		return err
	}
	if err = setDynamicSecretPasswordPolicyReadFields(d, rOut); err != nil {
		return err
	}

	d.SetId(path)

	return nil
}

func resourceDynamicSecretMssqlUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	mssqlDbname := d.Get("mssql_dbname").(string)
	mssqlUsername := d.Get("mssql_username").(string)
	mssqlPassword, err := common.EffectiveSecretValue(d, "mssql_password", "mssql_password_wo")
	if err != nil {
		return err
	}
	mssqlHost := d.Get("mssql_host").(string)
	mssqlPort := d.Get("mssql_port").(string)
	mssqlCreateStatements := d.Get("mssql_create_statements").(string)
	mssqlRevocationStatements := d.Get("mssql_revocation_statements").(string)
	mssqlAllowedDbNames := d.Get("mssql_allowed_db_names").(string)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	if secureAccessCertificateIssuer == "" {
		secureAccessCertificateIssuer = d.Get("secure_access_bastion_issuer").(string)
	}
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessDbSchema := d.Get("secure_access_db_schema").(string)
	secureAccessDelay := d.Get("secure_access_delay").(int)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.DynamicSecretUpdateMsSql{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.MssqlDbname, mssqlDbname)
	common.GetAkeylessPtr(&body.MssqlUsername, mssqlUsername)
	common.GetAkeylessPtr(&body.MssqlPassword, mssqlPassword)
	common.GetAkeylessPtr(&body.MssqlHost, mssqlHost)
	common.GetAkeylessPtr(&body.MssqlPort, mssqlPort)
	common.GetAkeylessPtr(&body.MssqlCreateStatements, mssqlCreateStatements)
	common.GetAkeylessPtr(&body.MssqlRevocationStatements, mssqlRevocationStatements)
	common.GetAkeylessPtr(&body.MssqlAllowedDbNames, mssqlAllowedDbNames)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		body.ItemCustomFields = &itemCustomFields
	}
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessDbSchema, secureAccessDbSchema)
	common.GetAkeylessPtr(&body.SecureAccessDelay, secureAccessDelay)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, resp, err := client.DynamicSecretUpdateMsSql(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretMssqlDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretMssqlImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretMssqlRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
