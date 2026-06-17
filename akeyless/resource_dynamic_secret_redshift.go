// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretRedshift() *schema.Resource {
	return &schema.Resource{
		Description: "Redshift dynamic secret resource",
		Create:      resourceDynamicSecretRedshiftCreate,
		Read:        resourceDynamicSecretRedshiftRead,
		Update:      resourceDynamicSecretRedshiftUpdate,
		Delete:      resourceDynamicSecretRedshiftDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretRedshiftImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic Secret name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Target name",
			},
			"redshift_db_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Redshift DB Name",
			},
			"redshift_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Redshift Username",
			},
			"redshift_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Redshift Password",
			},
			"redshift_host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Redshift Host",
				Default:     "127.0.0.1",
			},
			"redshift_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Redshift Port",
				Default:     "5439",
			},
			"creation_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Redshift Creation statements",
				Default:     "CREATE USER \"{{username}}\" WITH PASSWORD '{{password}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{username}}\";",
			},
			"ssl": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable/Disable SSL [true/false]",
				Default:     false,
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
				Description: "Dynamic producer encryption key",
			},
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customize how temporary usernames are generated using go template",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Target DB servers for connections (In case of Linked Target association, host(s) will inherit Linked Target hosts)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Enable Web Secure Remote Access",
			},
			"secure_access_db_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The DB Name",
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
		},
	}
}

func resourceDynamicSecretRedshiftCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	redshiftDbName := d.Get("redshift_db_name").(string)
	redshiftUsername := d.Get("redshift_username").(string)
	redshiftPassword := d.Get("redshift_password").(string)
	redshiftHost := d.Get("redshift_host").(string)
	redshiftPort := d.Get("redshift_port").(string)
	creationStatements := d.Get("creation_statements").(string)
	ssl := d.Get("ssl").(bool)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	producerEncryptionKey := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.DynamicSecretCreateRedshift{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.RedshiftDbName, redshiftDbName)
	common.GetAkeylessPtr(&body.RedshiftUsername, redshiftUsername)
	common.GetAkeylessPtr(&body.RedshiftPassword, redshiftPassword)
	common.GetAkeylessPtr(&body.RedshiftHost, redshiftHost)
	common.GetAkeylessPtr(&body.RedshiftPort, redshiftPort)
	common.GetAkeylessPtr(&body.CreationStatements, creationStatements)
	common.GetAkeylessPtr(&body.Ssl, ssl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKey, producerEncryptionKey)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		customFields := make(map[string]string)
		for k, v := range itemCustomFields {
			customFields[k] = v.(string)
		}
		common.GetAkeylessPtr(&body.ItemCustomFields, customFields)
	}

	_, resp, err := client.DynamicSecretCreateRedshift(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretRedshiftRead(d *schema.ResourceData, m interface{}) error {
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
		err = d.Set("redshift_db_name", *rOut.DbName)
		if err != nil {
			return err
		}
	}
	if rOut.DbUserName != nil {
		err = d.Set("redshift_username", *rOut.DbUserName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPwd != nil {
		err = d.Set("redshift_password", *rOut.DbPwd)
		if err != nil {
			return err
		}
	}
	if rOut.DbHostName != nil {
		err = d.Set("redshift_host", *rOut.DbHostName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPort != nil {
		err = d.Set("redshift_port", *rOut.DbPort)
		if err != nil {
			return err
		}
	}
	if rOut.RedshiftCreationStatements != nil {
		err = d.Set("creation_statements", *rOut.RedshiftCreationStatements)
		if err != nil {
			return err
		}
	}
	if rOut.SslConnectionMode != nil {
		err = d.Set("ssl", *rOut.SslConnectionMode)
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
		customFields := make(map[string]interface{})
		for _, field := range rOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		err = d.Set("item_custom_fields", customFields)
		if err != nil {
			return err
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceDynamicSecretRedshiftUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	redshiftDbName := d.Get("redshift_db_name").(string)
	redshiftUsername := d.Get("redshift_username").(string)
	redshiftPassword := d.Get("redshift_password").(string)
	redshiftHost := d.Get("redshift_host").(string)
	redshiftPort := d.Get("redshift_port").(string)
	creationStatements := d.Get("creation_statements").(string)
	ssl := d.Get("ssl").(bool)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	producerEncryptionKey := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.DynamicSecretUpdateRedshift{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.RedshiftDbName, redshiftDbName)
	common.GetAkeylessPtr(&body.RedshiftUsername, redshiftUsername)
	common.GetAkeylessPtr(&body.RedshiftPassword, redshiftPassword)
	common.GetAkeylessPtr(&body.RedshiftHost, redshiftHost)
	common.GetAkeylessPtr(&body.RedshiftPort, redshiftPort)
	common.GetAkeylessPtr(&body.CreationStatements, creationStatements)
	common.GetAkeylessPtr(&body.Ssl, ssl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKey, producerEncryptionKey)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		customFields := make(map[string]string)
		for k, v := range itemCustomFields {
			customFields[k] = v.(string)
		}
		common.GetAkeylessPtr(&body.ItemCustomFields, customFields)
	}

	_, resp, err := client.DynamicSecretUpdateRedshift(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretRedshiftDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretRedshiftImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretRedshiftRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
