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

func resourceProducerPostgresql() *schema.Resource {
	return &schema.Resource{
		Description:        "PostgreSQLproducer resource",
		DeprecationMessage: "Deprecated: Please use new resource: akeyless_dynamic_secret_postgresql",
		Create:             resourceProducerPostgresqlCreate,
		Read:               resourceProducerPostgresqlRead,
		Update:             resourceProducerPostgresqlUpdate,
		Delete:             resourceProducerPostgresqlDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerPostgresqlImport,
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
			"postgresql_db_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "PostgreSQL DB name",
			},
			"postgresql_username": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "PostgreSQL user",
			},
			"postgresql_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "PostgreSQL password",
			},
			"postgresql_host": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "PostgreSQL host name",
				Default:     "127.0.0.1",
			},
			"postgresql_port": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "PostgreSQL port",
				Default:     "5432",
			},
			"creation_statements": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "PostgreSQL Creation Statements",
				Default:     "CREATE USER \"{{name}}\" WITH PASSWORD '{{password}}';GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";GRANT CONNECT ON DATABASE postgres TO \"{{name}}\";GRANT USAGE ON SCHEMA public TO \"{{name}}\";",
			},
			"producer_encryption_key": {
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

func resourceProducerPostgresqlCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	postgresqlDbName := d.Get("postgresql_db_name").(string)
	postgresqlUsername := d.Get("postgresql_username").(string)
	postgresqlPassword := d.Get("postgresql_password").(string)
	postgresqlHost := d.Get("postgresql_host").(string)
	postgresqlPort := d.Get("postgresql_port").(string)
	creationStatements := d.Get("creation_statements").(string)
	producerEncryptionKey := d.Get("producer_encryption_key").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessDbSchema := d.Get("secure_access_db_schema").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.GatewayCreateProducerPostgreSQL{
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
	common.GetAkeylessPtr(&body.ProducerEncryptionKey, producerEncryptionKey)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessDbSchema, secureAccessDbSchema)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.GatewayCreateProducerPostgreSQL(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerPostgresqlRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.GatewayGetProducer{
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

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
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
		err = d.Set("postgresql_password", *rOut.DbPwd)
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
	if rOut.DynamicSecretKey != nil {
		err = d.Set("producer_encryption_key", *rOut.DynamicSecretKey)
		if err != nil {
			return err
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceProducerPostgresqlUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	postgresqlDbName := d.Get("postgresql_db_name").(string)
	postgresqlUsername := d.Get("postgresql_username").(string)
	postgresqlPassword := d.Get("postgresql_password").(string)
	postgresqlHost := d.Get("postgresql_host").(string)
	postgresqlPort := d.Get("postgresql_port").(string)
	creationStatements := d.Get("creation_statements").(string)
	producerEncryptionKey := d.Get("producer_encryption_key").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessDbSchema := d.Get("secure_access_db_schema").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.GatewayUpdateProducerPostgreSQL{
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
	common.GetAkeylessPtr(&body.ProducerEncryptionKey, producerEncryptionKey)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessDbSchema, secureAccessDbSchema)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.GatewayUpdateProducerPostgreSQL(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerPostgresqlDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.GatewayDeleteProducer{
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

func resourceProducerPostgresqlImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceProducerPostgresqlRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
