// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretOracle() *schema.Resource {
	return &schema.Resource{
		Description: "Oracle DB dynamic secret resource",
		Create:      resourceDynamicSecretOracleCreate,
		Read:        resourceDynamicSecretOracleRead,
		Update:      resourceDynamicSecretOracleUpdate,
		Delete:      resourceDynamicSecretOracleDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretOracleImport,
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
			"oracle_service_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Oracle service name",
			},
			"oracle_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Oracle user",
			},
			"oracle_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Oracle password",
			},
			"oracle_host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Oracle host name",
			},
			"oracle_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Oracle port",
				Default:     "1521",
			},
			"oracle_creation_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     `CREATE USER {{username}} IDENTIFIED BY "{{password}}"; GRANT CONNECT TO {{username}}; GRANT CREATE SESSION TO {{username}};`,
				Description: "Oracle Creation Statements",
			},
			"oracle_revocation_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     `REVOKE CONNECT FROM {{name}};REVOKE CREATE SESSION FROM {{name}};DROP USER {{name}};`,
				Description: "Oracle Revocation Statements",
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
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customize how temporary usernames are generated using go template",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"db_server_certificates": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "the set of root certificate authorities in base64 encoding that clients use when verifying server certificates",
			},
			"db_server_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Server name is used to verify the hostname on the returned certificates unless InsecureSkipVerify is given. It is also included in the client's handshake to support virtual hosting unless it is an IP address",
			},
		},
	}
}

func resourceDynamicSecretOracleCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	oracleServiceName := d.Get("oracle_service_name").(string)
	oracleUsername := d.Get("oracle_username").(string)
	oraclePassword := d.Get("oracle_password").(string)
	oracleHost := d.Get("oracle_host").(string)
	oraclePort := d.Get("oracle_port").(string)
	oracleScreationStatements := d.Get("oracle_creation_statements").(string)
	oracleRevocationStatements := d.Get("oracle_revocation_statements").(string)
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	dbServerCertificates := d.Get("db_server_certificates").(string)
	dbServerName := d.Get("db_server_name").(string)

	body := akeyless_api.DynamicSecretCreateOracleDb{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.OracleServiceName, oracleServiceName)
	common.GetAkeylessPtr(&body.OracleUsername, oracleUsername)
	common.GetAkeylessPtr(&body.OraclePassword, oraclePassword)
	common.GetAkeylessPtr(&body.OracleHost, oracleHost)
	common.GetAkeylessPtr(&body.OraclePort, oraclePort)
	common.GetAkeylessPtr(&body.OracleScreationStatements, oracleScreationStatements)
	common.GetAkeylessPtr(&body.OracleRevocationStatements, oracleRevocationStatements)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DbServerCertificates, dbServerCertificates)
	common.GetAkeylessPtr(&body.DbServerName, dbServerName)

	_, _, err := client.DynamicSecretCreateOracleDb(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretOracleRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
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
	if rOut.DbServerCertificates != nil {
		err = d.Set("db_server_certificates", *rOut.DbServerCertificates)
		if err != nil {
			return err
		}
	}
	if rOut.DbServerName != nil {
		err = d.Set("db_server_name", *rOut.DbServerName)
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
		err = d.Set("oracle_service_name", *rOut.DbName)
		if err != nil {
			return err
		}
	}
	if rOut.DbUserName != nil {
		err = d.Set("oracle_username", *rOut.DbUserName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPwd != nil {
		err = d.Set("oracle_password", *rOut.DbPwd)
		if err != nil {
			return err
		}
	}
	if rOut.DbHostName != nil {
		err = d.Set("oracle_host", *rOut.DbHostName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPort != nil {
		err = d.Set("oracle_port", *rOut.DbPort)
		if err != nil {
			return err
		}
	}
	if rOut.OracleCreationStatements != nil {
		err = d.Set("oracle_creation_statements", *rOut.OracleCreationStatements)
		if err != nil {
			return err
		}
	}
	if rOut.OracleRevocationStatements != nil {
		err = d.Set("oracle_revocation_statements", *rOut.OracleRevocationStatements)
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

	if rOut.UsernameTemplate != nil {
		err = d.Set("custom_username_template", *rOut.UsernameTemplate)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceDynamicSecretOracleUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	oracleServiceName := d.Get("oracle_service_name").(string)
	oracleUsername := d.Get("oracle_username").(string)
	oraclePassword := d.Get("oracle_password").(string)
	oracleHost := d.Get("oracle_host").(string)
	oraclePort := d.Get("oracle_port").(string)
	oracleScreationStatements := d.Get("oracle_creation_statements").(string)
	oracleRevocationStatements := d.Get("oracle_revocation_statements").(string)
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	dbServerCertificates := d.Get("db_server_certificates").(string)
	dbServerName := d.Get("db_server_name").(string)

	body := akeyless_api.DynamicSecretUpdateOracleDb{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.OracleServiceName, oracleServiceName)
	common.GetAkeylessPtr(&body.OracleUsername, oracleUsername)
	common.GetAkeylessPtr(&body.OraclePassword, oraclePassword)
	common.GetAkeylessPtr(&body.OracleHost, oracleHost)
	common.GetAkeylessPtr(&body.OraclePort, oraclePort)
	common.GetAkeylessPtr(&body.OracleScreationStatements, oracleScreationStatements)
	common.GetAkeylessPtr(&body.OracleRevocationStatements, oracleRevocationStatements)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DbServerCertificates, dbServerCertificates)
	common.GetAkeylessPtr(&body.DbServerName, dbServerName)

	_, _, err := client.DynamicSecretUpdateOracleDb(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretOracleDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretOracleImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretOracleRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
