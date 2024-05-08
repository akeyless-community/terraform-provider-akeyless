// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceProducerMysql() *schema.Resource {
	return &schema.Resource{
		Description:        "MySQL producer resource",
		DeprecationMessage: "Deprecated: Please use new resource: akeyless_dynamic_secret_mysql",
		Create:             resourceProducerMysqlCreate,
		Read:               resourceProducerMysqlRead,
		Update:             resourceProducerMysqlUpdate,
		Delete:             resourceProducerMysqlDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerMysqlImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Producer name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Name of existing target to use in producer creation",
			},
			"mysql_dbname": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MySQL DB name",
			},
			"mysql_username": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MySQL user",
			},
			"mysql_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Sensitive:   true,
				Description: "MySQL password",
			},
			"mysql_host": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MySQL host name",
				Default:     "127.0.0.1",
			},
			"mysql_port": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MySQL port",
				Default:     "3306",
			},
			"mysql_screation_statements": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "MySQL Creation Statements",
			},
			"producer_encryption_key_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Encrypt producer with following key",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"tags": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"db_server_certificates": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "the set of root certificate authorities in base64 encoding that clients use when verifying server certificates",
			},
			"db_server_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Server name is used to verify the hostname on the returned certificates unless InsecureSkipVerify is given. It is also included in the client's handshake to support virtual hosting unless it is an IP address",
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_bastion_issuer": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Bastion",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "Target DB servers for connections., For multiple values repeat this flag.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable Web Secure Remote Access ",
				Default:     "false",
			},
			"secure_access_db_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Enable Web Secure Remote Access ",
				Computed:    true,
			},
		},
	}
}

func resourceProducerMysqlCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	mysqlDbname := d.Get("mysql_dbname").(string)
	mysqlUsername := d.Get("mysql_username").(string)
	mysqlPassword := d.Get("mysql_password").(string)
	mysqlHost := d.Get("mysql_host").(string)
	mysqlPort := d.Get("mysql_port").(string)
	mysqlScreationStatements := d.Get("mysql_screation_statements").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	dbServerCertificates := d.Get("db_server_certificates").(string)
	dbServerName := d.Get("db_server_name").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.GatewayCreateProducerMySQL{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.MysqlDbname, mysqlDbname)
	common.GetAkeylessPtr(&body.MysqlUsername, mysqlUsername)
	common.GetAkeylessPtr(&body.MysqlPassword, mysqlPassword)
	common.GetAkeylessPtr(&body.MysqlHost, mysqlHost)
	common.GetAkeylessPtr(&body.MysqlPort, mysqlPort)
	common.GetAkeylessPtr(&body.MysqlScreationStatements, mysqlScreationStatements)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DbServerCertificates, dbServerCertificates)
	common.GetAkeylessPtr(&body.DbServerName, dbServerName)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.GatewayCreateProducerMySQL(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerMysqlRead(d *schema.ResourceData, m interface{}) error {
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
		err = d.Set("mysql_screation_statements", *rOut.MysqlCreationStatements)
		if err != nil {
			return err
		}
	}
	if rOut.DynamicSecretKey != nil {
		err = d.Set("producer_encryption_key_name", *rOut.DynamicSecretKey)
		if err != nil {
			return err
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceProducerMysqlUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	mysqlDbname := d.Get("mysql_dbname").(string)
	mysqlUsername := d.Get("mysql_username").(string)
	mysqlPassword := d.Get("mysql_password").(string)
	mysqlHost := d.Get("mysql_host").(string)
	mysqlPort := d.Get("mysql_port").(string)
	mysqlScreationStatements := d.Get("mysql_screation_statements").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	dbServerCertificates := d.Get("db_server_certificates").(string)
	dbServerName := d.Get("db_server_name").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.GatewayUpdateProducerMySQL{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.MysqlDbname, mysqlDbname)
	common.GetAkeylessPtr(&body.MysqlUsername, mysqlUsername)
	common.GetAkeylessPtr(&body.MysqlPassword, mysqlPassword)
	common.GetAkeylessPtr(&body.MysqlHost, mysqlHost)
	common.GetAkeylessPtr(&body.MysqlPort, mysqlPort)
	common.GetAkeylessPtr(&body.MysqlScreationStatements, mysqlScreationStatements)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DbServerCertificates, dbServerCertificates)
	common.GetAkeylessPtr(&body.DbServerName, dbServerName)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.GatewayUpdateProducerMySQL(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerMysqlDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.GatewayDeleteProducer{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.GatewayDeleteProducer(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceProducerMysqlImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceProducerMysqlRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
