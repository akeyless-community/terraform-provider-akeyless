// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretMssql() *schema.Resource {
	return &schema.Resource{
		Description: "Microsoft SQL Server producer resource",
		Create:      resourceDynamicSecretMssqlCreate,
		Read:        resourceDynamicSecretMssqlRead,
		Update:      resourceDynamicSecretMssqlUpdate,
		Delete:      resourceDynamicSecretMssqlDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretMssqlImport,
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
				Description: "Name of existing target to use in producer creation",
			},
			"mssql_dbname": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MSSQL Server DB Name",
			},
			"mssql_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MS SQL Server user",
			},
			"mssql_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MS SQL Server password",
			},
			"mssql_host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MS SQL Server host name",
				Default:     "127.0.0.1",
			},
			"mssql_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MS SQL Server port",
				Default:     "1433",
			},
			"mssql_create_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MSSQL Server Creation Statements",
				Default:     `CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';`,
			},
			"mssql_revocation_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MSSQL Server Revocation Statements",
				Default:     `DROP LOGIN [{{name}}];`,
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
			"encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Encrypt dynamic secret details with following key",
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
			"secure_access_bastion_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Bastion",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Target DB servers for connections., For multiple values repeat this flag.",
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
				Description: "Enable Web Secure Remote Access ",
				Default:     "false",
			},
			"secure_access_db_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable Web Secure Remote Access ",
				Computed:    true,
			},
		},
	}
}

func resourceDynamicSecretMssqlCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	mssqlDbname := d.Get("mssql_dbname").(string)
	mssqlUsername := d.Get("mssql_username").(string)
	mssqlPassword := d.Get("mssql_password").(string)
	mssqlHost := d.Get("mssql_host").(string)
	mssqlPort := d.Get("mssql_port").(string)
	mssqlCreateStatements := d.Get("mssql_create_statements").(string)
	mssqlRevocationStatements := d.Get("mssql_revocation_statements").(string)
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessDbSchema := d.Get("secure_access_db_schema").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.DynamicSecretCreateMsSql{
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
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessDbSchema, secureAccessDbSchema)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.DynamicSecretCreateMsSql(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretMssqlRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GatewayGetProducer{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GatewayGetProducer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
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
		err = d.Set("tags", *rOut.Tags)
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
		err = d.Set("mssql_password", *rOut.DbPwd)
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
		err = d.Set("encryption_key_name", *rOut.DynamicSecretKey)
		if err != nil {
			return err
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceDynamicSecretMssqlUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	mssqlDbname := d.Get("mssql_dbname").(string)
	mssqlUsername := d.Get("mssql_username").(string)
	mssqlPassword := d.Get("mssql_password").(string)
	mssqlHost := d.Get("mssql_host").(string)
	mssqlPort := d.Get("mssql_port").(string)
	mssqlCreateStatements := d.Get("mssql_create_statements").(string)
	mssqlRevocationStatements := d.Get("mssql_revocation_statements").(string)
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessDbSchema := d.Get("secure_access_db_schema").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.DynamicSecretUpdateMsSql{
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
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessDbSchema, secureAccessDbSchema)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.DynamicSecretUpdateMsSql(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretMssqlDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretMssqlImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	return resourceDynamicSecretImport(d, m)
}
