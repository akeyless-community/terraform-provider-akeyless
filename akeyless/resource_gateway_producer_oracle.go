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

func resourceProducerOracle() *schema.Resource {
	return &schema.Resource{
		Description:        "Oracle DB producer resource",
		DeprecationMessage: "Deprecated: Please use new resource: akeyless_dynamic_secret_oracle",
		Create:             resourceProducerOracleCreate,
		Read:               resourceProducerOracleRead,
		Update:             resourceProducerOracleUpdate,
		Delete:             resourceProducerOracleDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerOracleImport,
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
			"oracle_service_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Oracle service name",
			},
			"oracle_username": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Oracle user",
			},
			"oracle_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Oracle password",
			},
			"oracle_host": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Oracle host name",
				Default:     "127.0.0.1",
			},
			"oracle_port": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Oracle port",
				Default:     "1521",
			},
			"oracle_screation_statements": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Oracle Creation Statements",
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
		},
	}
}

func resourceProducerOracleCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	oracleServiceName := d.Get("oracle_service_name").(string)
	oracleUsername := d.Get("oracle_username").(string)
	oraclePassword := d.Get("oracle_password").(string)
	oracleHost := d.Get("oracle_host").(string)
	oraclePort := d.Get("oracle_port").(string)
	oracleScreationStatements := d.Get("oracle_screation_statements").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	dbServerCertificates := d.Get("db_server_certificates").(string)
	dbServerName := d.Get("db_server_name").(string)

	body := akeyless.GatewayCreateProducerOracleDb{
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
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DbServerCertificates, dbServerCertificates)
	common.GetAkeylessPtr(&body.DbServerName, dbServerName)

	_, _, err := client.GatewayCreateProducerOracleDb(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerOracleRead(d *schema.ResourceData, m interface{}) error {
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
		err = d.Set("oracle_screation_statements", *rOut.OracleCreationStatements)
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

	d.SetId(path)

	return nil
}

func resourceProducerOracleUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	oracleServiceName := d.Get("oracle_service_name").(string)
	oracleUsername := d.Get("oracle_username").(string)
	oraclePassword := d.Get("oracle_password").(string)
	oracleHost := d.Get("oracle_host").(string)
	oraclePort := d.Get("oracle_port").(string)
	oracleScreationStatements := d.Get("oracle_screation_statements").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	dbServerCertificates := d.Get("db_server_certificates").(string)
	dbServerName := d.Get("db_server_name").(string)

	body := akeyless.GatewayUpdateProducerOracleDb{
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
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DbServerCertificates, dbServerCertificates)
	common.GetAkeylessPtr(&body.DbServerName, dbServerName)

	_, _, err := client.GatewayUpdateProducerOracleDb(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerOracleDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceProducerOracleImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceProducerOracleRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
