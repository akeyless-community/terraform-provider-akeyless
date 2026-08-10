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

func resourceDynamicSecretPostgresql() *schema.Resource {
	return &schema.Resource{
		Description: "PostgreSQL dynamic secret resource",
		Create:      resourceDynamicSecretPostgresqlCreate,
		Read:        resourceDynamicSecretPostgresqlRead,
		Update:      resourceDynamicSecretPostgresqlUpdate,
		Delete:      resourceDynamicSecretPostgresqlDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretPostgresqlImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("postgresql_password"), cty.GetAttrPath("postgresql_password_wo")),
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
				Description: "Target name",
			},
			"postgresql_db_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PostgreSQL DB Name",
			},
			"postgresql_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PostgreSQL Username",
			},
			"postgresql_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "PostgreSQL Password",
			},
			"postgresql_password_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"postgresql_password_wo_version"},
				WriteOnly:    true,
				Description:  "PostgreSQL Password (write-only, not stored in state). Requires Terraform 1.11+. Bump postgresql_password_wo_version to change it.",
			},
			"postgresql_password_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"postgresql_password_wo"},
				Description:  "Version trigger for postgresql_password_wo. Increment to update the value.",
			},
			"postgresql_host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PostgreSQL Host",
				Default:     "127.0.0.1",
			},
			"postgresql_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PostgreSQL Port",
				Default:     "5432",
			},
			"creation_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PostgreSQL Creation statements",
				Default:     `CREATE USER "{{name}}" WITH PASSWORD '{{password}}';GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";GRANT CONNECT ON DATABASE postgres TO "{{name}}";GRANT USAGE ON SCHEMA public TO "{{name}}";`,
			},
			"revocation_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PostgreSQL Revocation statements",
				Default:     `REASSIGN OWNED BY "{{name}}" TO {{userHost}}; DROP OWNED BY "{{name}}"; select pg_terminate_backend(pid) from pg_stat_activity where usename = '{{name}}'; DROP USER "{{name}}";`,
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
			"secure_access_db_schema": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The db schema",
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
			"secure_access_delay": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The delay duration, in seconds, to wait after generating just-in-time credentials. Accepted range: 0-120 seconds",
			},
		},
	}
}

func resourceDynamicSecretPostgresqlCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	postgresqlDbName := d.Get("postgresql_db_name").(string)
	postgresqlUsername := d.Get("postgresql_username").(string)
	postgresqlPassword, err := common.EffectiveSecretValue(d, "postgresql_password", "postgresql_password_wo")
	if err != nil {
		return err
	}
	postgresqlHost := d.Get("postgresql_host").(string)
	postgresqlPort := d.Get("postgresql_port").(string)
	creationStatements := d.Get("creation_statements").(string)
	revocationStatements := d.Get("revocation_statements").(string)
	ssl := d.Get("ssl").(bool)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	producerEncryptionKey := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessDbSchema := d.Get("secure_access_db_schema").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	if secureAccessCertificateIssuer == "" {
		secureAccessCertificateIssuer = d.Get("secure_access_bastion_issuer").(string)
	}
	secureAccessDelay := d.Get("secure_access_delay").(int)

	body := akeyless_api.DynamicSecretCreatePostgreSql{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.PostgresqlDbName, postgresqlDbName)
	common.GetAkeylessPtr(&body.PostgresqlUsername, postgresqlUsername)
	common.GetAkeylessPtr(&body.PostgresqlPassword, postgresqlPassword)
	common.GetAkeylessPtr(&body.PostgresqlHost, postgresqlHost)
	common.GetAkeylessPtr(&body.PostgresqlPort, postgresqlPort)
	common.GetAkeylessPtr(&body.CreationStatements, creationStatements)
	common.GetAkeylessPtr(&body.RevocationStatement, revocationStatements)
	common.GetAkeylessPtr(&body.Ssl, ssl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKey, producerEncryptionKey)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessDbSchema, secureAccessDbSchema)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		common.GetAkeylessPtr(&body.ItemCustomFields, fields)
	}
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	if secureAccessDelay > 0 {
		delay := int64(secureAccessDelay)
		common.GetAkeylessPtr(&body.SecureAccessDelay, delay)
	}

	_, resp, err := client.DynamicSecretCreatePostgreSql(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretPostgresqlRead(d *schema.ResourceData, m interface{}) error {
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
		err = d.Set("postgresql_db_name", *rOut.DbName)
		if err != nil {
			return err
		}
	}
	if rOut.DbUserName != nil {
		err = d.Set("postgresql_username", *rOut.DbUserName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPwd != nil {
		err = common.SetSecretFromRead(d, "postgresql_password", "postgresql_password_wo", "postgresql_password_wo_version", *rOut.DbPwd)
		if err != nil {
			return err
		}
	}
	if rOut.DbHostName != nil {
		err = d.Set("postgresql_host", *rOut.DbHostName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPort != nil {
		err = d.Set("postgresql_port", *rOut.DbPort)
		if err != nil {
			return err
		}
	}
	if rOut.PostgresCreationStatements != nil {
		err = d.Set("creation_statements", *rOut.PostgresCreationStatements)
		if err != nil {
			return err
		}
	}
	if rOut.PostgresRevocationStatements != nil {
		err = d.Set("revocation_statements", *rOut.PostgresRevocationStatements)
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
		fields := make(map[string]interface{})
		for _, field := range rOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				fields[*field.Name] = *field.Value
			}
		}
		err = d.Set("item_custom_fields", fields)
		if err != nil {
			return err
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	if rOut.SecureRemoteAccessDetails != nil {
		sra := rOut.SecureRemoteAccessDetails
		if sra.BastionIssuer != nil {
			err = d.Set("secure_access_certificate_issuer", *sra.BastionIssuer)
			if err != nil {
				return err
			}
		}
		if sra.ConnectionDelaySeconds != nil {
			err = d.Set("secure_access_delay", int(*sra.ConnectionDelaySeconds))
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

func resourceDynamicSecretPostgresqlUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	postgresqlDbName := d.Get("postgresql_db_name").(string)
	postgresqlUsername := d.Get("postgresql_username").(string)
	postgresqlPassword, err := common.SecretValueForUpdate(d, "postgresql_password", "postgresql_password_wo")
	if err != nil {
		return err
	}
	postgresqlHost := d.Get("postgresql_host").(string)
	postgresqlPort := d.Get("postgresql_port").(string)
	creationStatements := d.Get("creation_statements").(string)
	revocationStatements := d.Get("revocation_statements").(string)
	ssl := d.Get("ssl").(bool)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	producerEncryptionKey := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessDbSchema := d.Get("secure_access_db_schema").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	if secureAccessCertificateIssuer == "" {
		secureAccessCertificateIssuer = d.Get("secure_access_bastion_issuer").(string)
	}
	secureAccessDelay := d.Get("secure_access_delay").(int)

	body := akeyless_api.DynamicSecretUpdatePostgreSql{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.PostgresqlDbName, postgresqlDbName)
	common.GetAkeylessPtr(&body.PostgresqlUsername, postgresqlUsername)
	common.SetOptionalString(&body.PostgresqlPassword, postgresqlPassword)
	common.GetAkeylessPtr(&body.PostgresqlHost, postgresqlHost)
	common.GetAkeylessPtr(&body.PostgresqlPort, postgresqlPort)
	common.GetAkeylessPtr(&body.CreationStatements, creationStatements)
	common.GetAkeylessPtr(&body.RevocationStatement, revocationStatements)
	common.GetAkeylessPtr(&body.Ssl, ssl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKey, producerEncryptionKey)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessDbSchema, secureAccessDbSchema)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		common.GetAkeylessPtr(&body.ItemCustomFields, fields)
	}
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	if secureAccessDelay > 0 {
		delay := int64(secureAccessDelay)
		common.GetAkeylessPtr(&body.SecureAccessDelay, delay)
	}

	_, resp, err := client.DynamicSecretUpdatePostgreSql(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretPostgresqlDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretPostgresqlImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretPostgresqlRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
