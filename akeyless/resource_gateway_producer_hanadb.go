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

func resourceProducerHanadb() *schema.Resource {
	return &schema.Resource{
		Description: "HanaDB producer resource",
		Create:      resourceProducerHanadbCreate,
		Read:        resourceProducerHanadbRead,
		Update:      resourceProducerHanadbUpdate,
		Delete:      resourceProducerHanadbDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerHanadbImport,
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
			"hana_dbname": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Hana DB Name",
			},
			"hanadb_username": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "HanaDB user",
			},
			"hanadb_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "HanaDB password",
			},
			"hanadb_host": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "HanaDB host name",
				Default:     "127.0.0.1",
			},
			"hanadb_port": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "HanaDB port",
				Default:     "443",
			},
			"hanadb_create_statements": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "HanaDB Creation Statements",
				Default:     `CREATE USER {{name}} PASSWORD "{{password}}"; GRANT "MONITOR ADMIN" TO {{name}};`,
			},
			"hanadb_revocation_statements": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "HanaDB Revocation Statements",
				Default:     "DROP USER {{name}};",
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
			"secure_access_db_schema": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The db schema",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable Web Secure Remote Access ",
				Default:     "false",
			},
		},
	}
}

func resourceProducerHanadbCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	hanaDbname := d.Get("hana_dbname").(string)
	hanadbUsername := d.Get("hanadb_username").(string)
	hanadbPassword := d.Get("hanadb_password").(string)
	hanadbHost := d.Get("hanadb_host").(string)
	hanadbPort := d.Get("hanadb_port").(string)
	hanadbCreateStatements := d.Get("hanadb_create_statements").(string)
	hanadbRevocationStatements := d.Get("hanadb_revocation_statements").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessDbSchema := d.Get("secure_access_db_schema").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.GatewayCreateProducerHanaDb{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.HanaDbname, hanaDbname)
	common.GetAkeylessPtr(&body.HanadbUsername, hanadbUsername)
	common.GetAkeylessPtr(&body.HanadbPassword, hanadbPassword)
	common.GetAkeylessPtr(&body.HanadbHost, hanadbHost)
	common.GetAkeylessPtr(&body.HanadbPort, hanadbPort)
	common.GetAkeylessPtr(&body.HanadbCreateStatements, hanadbCreateStatements)
	common.GetAkeylessPtr(&body.HanadbRevocationStatements, hanadbRevocationStatements)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessDbSchema, secureAccessDbSchema)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.GatewayCreateProducerHanaDb(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerHanadbRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.HanadbRevocationStatements != nil {
		err = d.Set("hanadb_revocation_statements", *rOut.HanadbRevocationStatements)
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
		err = d.Set("hana_dbname", *rOut.DbName)
		if err != nil {
			return err
		}
	}
	if rOut.DbUserName != nil {
		err = d.Set("hanadb_username", *rOut.DbUserName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPwd != nil {
		err = d.Set("hanadb_password", *rOut.DbPwd)
		if err != nil {
			return err
		}
	}
	if rOut.DbHostName != nil {
		err = d.Set("hanadb_host", *rOut.DbHostName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPort != nil {
		err = d.Set("hanadb_port", *rOut.DbPort)
		if err != nil {
			return err
		}
	}
	if rOut.HanadbCreationStatements != nil {
		err = d.Set("hanadb_create_statements", *rOut.HanadbCreationStatements)
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

func resourceProducerHanadbUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	hanaDbname := d.Get("hana_dbname").(string)
	hanadbUsername := d.Get("hanadb_username").(string)
	hanadbPassword := d.Get("hanadb_password").(string)
	hanadbHost := d.Get("hanadb_host").(string)
	hanadbPort := d.Get("hanadb_port").(string)
	hanadbCreateStatements := d.Get("hanadb_create_statements").(string)
	hanadbRevocationStatements := d.Get("hanadb_revocation_statements").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessDbSchema := d.Get("secure_access_db_schema").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.GatewayUpdateProducerHanaDb{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.HanaDbname, hanaDbname)
	common.GetAkeylessPtr(&body.HanadbUsername, hanadbUsername)
	common.GetAkeylessPtr(&body.HanadbPassword, hanadbPassword)
	common.GetAkeylessPtr(&body.HanadbHost, hanadbHost)
	common.GetAkeylessPtr(&body.HanadbPort, hanadbPort)
	common.GetAkeylessPtr(&body.HanadbCreateStatements, hanadbCreateStatements)
	common.GetAkeylessPtr(&body.HanadbRevocationStatements, hanadbRevocationStatements)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessDbSchema, secureAccessDbSchema)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.GatewayUpdateProducerHanaDb(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update producer: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update producer: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerHanadbDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceProducerHanadbImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GatewayGetProducer{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GatewayGetProducer(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
