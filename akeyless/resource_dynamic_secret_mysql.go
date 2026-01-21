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

func resourceDynamicSecretMysql() *schema.Resource {
	return &schema.Resource{
		Description: "MySQL dynamic secret resource",
		Create:      resourceDynamicSecretMysqlCreate,
		Read:        resourceDynamicSecretMysqlRead,
		Update:      resourceDynamicSecretMysqlUpdate,
		Delete:      resourceDynamicSecretMysqlDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretMysqlImport,
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
			"mysql_dbname": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MySQL DB name",
			},
			"mysql_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MySQL user",
			},
			"mysql_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "MySQL password",
			},
			"mysql_host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MySQL host name",
			},
			"mysql_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MySQL port",
				Default:     "3306",
			},
			"mysql_creation_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     `CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}' PASSWORD EXPIRE INTERVAL 30 DAY;GRANT SELECT ON *.* TO '{{name}}'@'%';`,
				Description: "MySQL Creation Statements",
			},
			"mysql_revocation_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     `REVOKE ALL PRIVILEGES, GRANT OPTION FROM '{{name}}'@'%'; DROP USER '{{name}}'@'%';`,
				Description: "MySQL Revocation Statements",
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
			"ssl": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable/Disable SSL [true/false]",
				Default:     "false",
			},
			"ssl_certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "SSL CA certificate in base64 encoding generated from a trusted Certificate Authority (CA)",
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
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     "false",
				Description: "Enable Web Secure Remote Access",
			},
			"secure_access_db_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Enable Web Secure Remote Access",
			},
		},
	}
}

func resourceDynamicSecretMysqlCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	mysqlDbname := d.Get("mysql_dbname").(string)
	mysqlUsername := d.Get("mysql_username").(string)
	mysqlPassword := d.Get("mysql_password").(string)
	mysqlHost := d.Get("mysql_host").(string)
	mysqlPort := d.Get("mysql_port").(string)
	creationStatements := d.Get("mysql_creation_statements").(string)
	revocationStatements := d.Get("mysql_revocation_statements").(string)
	ssl := d.Get("ssl").(bool)
	sslCertificate := d.Get("ssl_certificate").(string)
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	dbServerCertificates := d.Get("db_server_certificates").(string)
	dbServerName := d.Get("db_server_name").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.DynamicSecretCreateMySql{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.MysqlDbname, mysqlDbname)
	common.GetAkeylessPtr(&body.MysqlUsername, mysqlUsername)
	common.GetAkeylessPtr(&body.MysqlPassword, mysqlPassword)
	common.GetAkeylessPtr(&body.MysqlHost, mysqlHost)
	common.GetAkeylessPtr(&body.MysqlPort, mysqlPort)
	common.GetAkeylessPtr(&body.MysqlScreationStatements, creationStatements)
	common.GetAkeylessPtr(&body.MysqlRevocationStatements, revocationStatements)
	common.GetAkeylessPtr(&body.Ssl, ssl)
	common.GetAkeylessPtr(&body.SslCertificate, sslCertificate)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DbServerCertificates, dbServerCertificates)
	common.GetAkeylessPtr(&body.DbServerName, dbServerName)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.DynamicSecretCreateMySql(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretMysqlRead(d *schema.ResourceData, m interface{}) error {
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
		err = common.SetDataByPrefixSlash(d, "target_name", targetName, d.Get("target_name").(string))
		if err != nil {
			return err
		}
	}
	if rOut.DbName != nil {
		err = d.Set("mysql_dbname", *rOut.DbName)
		if err != nil {
			return err
		}
	}
	if rOut.DbUserName != nil {
		err = d.Set("mysql_username", *rOut.DbUserName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPwd != nil {
		err = d.Set("mysql_password", *rOut.DbPwd)
		if err != nil {
			return err
		}
	}
	if rOut.DbHostName != nil {
		err = d.Set("mysql_host", *rOut.DbHostName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPort != nil {
		err = d.Set("mysql_port", *rOut.DbPort)
		if err != nil {
			return err
		}
	}
	if rOut.MysqlCreationStatements != nil {
		err = d.Set("mysql_creation_statements", *rOut.MysqlCreationStatements)
		if err != nil {
			return err
		}
	}
	if rOut.MysqlRevocationStatements != nil {
		err = d.Set("mysql_revocation_statements", *rOut.MysqlRevocationStatements)
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
	if rOut.SslConnectionCertificate != nil {
		err = d.Set("ssl_certificate", *rOut.SslConnectionCertificate)
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

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceDynamicSecretMysqlUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	mysqlDbname := d.Get("mysql_dbname").(string)
	mysqlUsername := d.Get("mysql_username").(string)
	mysqlPassword := d.Get("mysql_password").(string)
	mysqlHost := d.Get("mysql_host").(string)
	mysqlPort := d.Get("mysql_port").(string)
	creationStatements := d.Get("mysql_creation_statements").(string)
	revocationStatements := d.Get("mysql_revocation_statements").(string)
	ssl := d.Get("ssl").(bool)
	sslCertificate := d.Get("ssl_certificate").(string)
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	dbServerCertificates := d.Get("db_server_certificates").(string)
	dbServerName := d.Get("db_server_name").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.DynamicSecretUpdateMySql{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.MysqlDbname, mysqlDbname)
	common.GetAkeylessPtr(&body.MysqlUsername, mysqlUsername)
	common.GetAkeylessPtr(&body.MysqlPassword, mysqlPassword)
	common.GetAkeylessPtr(&body.MysqlHost, mysqlHost)
	common.GetAkeylessPtr(&body.MysqlPort, mysqlPort)
	common.GetAkeylessPtr(&body.MysqlScreationStatements, creationStatements)
	common.GetAkeylessPtr(&body.MysqlRevocationStatements, revocationStatements)
	common.GetAkeylessPtr(&body.Ssl, ssl)
	common.GetAkeylessPtr(&body.SslCertificate, sslCertificate)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DbServerCertificates, dbServerCertificates)
	common.GetAkeylessPtr(&body.DbServerName, dbServerName)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.DynamicSecretUpdateMySql(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretMysqlDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretMysqlImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretMysqlRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
