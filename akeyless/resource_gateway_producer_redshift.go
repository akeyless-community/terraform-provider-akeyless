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

func resourceProducerRedshift() *schema.Resource {
	return &schema.Resource{
		Description: "Redshift producer resource",
		Create:      resourceProducerRedshiftCreate,
		Read:        resourceProducerRedshiftRead,
		Update:      resourceProducerRedshiftUpdate,
		Delete:      resourceProducerRedshiftDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerRedshiftImport,
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
			"redshift_db_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Redshift DB name",
			},
			"redshift_username": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "redshiftL user",
			},
			"redshift_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Redshift password",
			},
			"redshift_host": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Redshift host name",
				Default:     "127.0.0.1",
			},
			"redshift_port": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Redshift port",
				Default:     "5439",
			},
			"creation_statements": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Redshift Creation Statements",
				Default:     "CREATE USER \"{{username}}\" WITH PASSWORD '{{password}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{username}}\";",
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
			"secure_access_enable": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "Target DB servers for connections., For multiple values repeat this flag.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"tags": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable Web Secure Remote Access ",
				Computed:    true,
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

func resourceProducerRedshiftCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	redshiftDbName := d.Get("redshift_db_name").(string)
	redshiftUsername := d.Get("redshift_username").(string)
	redshiftPassword := d.Get("redshift_password").(string)
	redshiftHost := d.Get("redshift_host").(string)
	redshiftPort := d.Get("redshift_port").(string)
	creationStatements := d.Get("creation_statements").(string)
	producerEncryptionKey := d.Get("producer_encryption_key").(string)
	userTtl := d.Get("user_ttl").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless.GatewayCreateProducerRedshift{
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
	common.GetAkeylessPtr(&body.ProducerEncryptionKey, producerEncryptionKey)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.Tags, tags)

	_, _, err := client.GatewayCreateProducerRedshift(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerRedshiftRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
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

func resourceProducerRedshiftUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	redshiftDbName := d.Get("redshift_db_name").(string)
	redshiftUsername := d.Get("redshift_username").(string)
	redshiftPassword := d.Get("redshift_password").(string)
	redshiftHost := d.Get("redshift_host").(string)
	redshiftPort := d.Get("redshift_port").(string)
	creationStatements := d.Get("creation_statements").(string)
	producerEncryptionKey := d.Get("producer_encryption_key").(string)
	userTtl := d.Get("user_ttl").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless.GatewayUpdateProducerRedshift{
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
	common.GetAkeylessPtr(&body.ProducerEncryptionKey, producerEncryptionKey)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.Tags, tags)

	_, _, err := client.GatewayUpdateProducerRedshift(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerRedshiftDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceProducerRedshiftImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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
