// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceProducerCassandra() *schema.Resource {
	return &schema.Resource{
		Description:        "Cassandra producer resource",
		DeprecationMessage: "Deprecated: Please use new resource: akeyless_dynamic_secret_cassandra",
		Create:             resourceProducerCassandraCreate,
		Read:               resourceProducerCassandraRead,
		Update:             resourceProducerCassandraUpdate,
		Delete:             resourceProducerCassandraDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerCassandraImport,
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
				Description: "Target name",
			},
			"cassandra_hosts": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Cassandra hosts names or IP addresses, comma separated",
			},
			"cassandra_username": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Cassandra superuser user name",
			},
			"cassandra_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Cassandra superuser password",
			},
			"cassandra_port": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Cassandra port",
				Default:     "9042",
			},
			"cassandra_creation_statements": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Cassandra Creation Statements",
				Default:     "CREATE ROLE '{{username}}' WITH PASSWORD = '{{password}}' AND LOGIN = true; GRANT SELECT ON ALL KEYSPACES TO '{{username}}';",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "User TTL (<=60m for access token)",
				Default:     "60m",
			},
			"tags": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"producer_encryption_key_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Dynamic producer encryption key",
			},
		},
	}
}

func resourceProducerCassandraCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client

	ctx := context.Background()
	token, err := provider.getToken(ctx, d)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	var apiErr akeyless_api.GenericOpenAPIError

	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	cassandraHosts := d.Get("cassandra_hosts").(string)
	cassandraUsername := d.Get("cassandra_username").(string)
	cassandraPassword := d.Get("cassandra_password").(string)
	cassandraPort := d.Get("cassandra_port").(string)
	cassandraCreationStatements := d.Get("cassandra_creation_statements").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)

	body := akeyless_api.GatewayCreateProducerCassandra{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.CassandraHosts, cassandraHosts)
	common.GetAkeylessPtr(&body.CassandraUsername, cassandraUsername)
	common.GetAkeylessPtr(&body.CassandraPassword, cassandraPassword)
	common.GetAkeylessPtr(&body.CassandraPort, cassandraPort)
	common.GetAkeylessPtr(&body.CassandraCreationStatements, cassandraCreationStatements)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)

	_, _, err = client.GatewayCreateProducerCassandra(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerCassandraRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client

	ctx := context.Background()
	token, err := provider.getToken(ctx, d)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	var apiErr akeyless_api.GenericOpenAPIError

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
	if rOut.CassandraCreationStatements != nil {
		err = d.Set("cassandra_creation_statements", *rOut.CassandraCreationStatements)
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
	if rOut.DbHostName != nil {
		err = d.Set("cassandra_hosts", *rOut.DbHostName)
		if err != nil {
			return err
		}
	}
	if rOut.DbUserName != nil {
		err = d.Set("cassandra_username", *rOut.DbUserName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPwd != nil {
		err = d.Set("cassandra_password", *rOut.DbPwd)
		if err != nil {
			return err
		}
	}
	if rOut.DbPort != nil {
		err = d.Set("cassandra_port", *rOut.DbPort)
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

func resourceProducerCassandraUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client

	ctx := context.Background()
	token, err := provider.getToken(ctx, d)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	var apiErr akeyless_api.GenericOpenAPIError

	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	cassandraHosts := d.Get("cassandra_hosts").(string)
	cassandraUsername := d.Get("cassandra_username").(string)
	cassandraPassword := d.Get("cassandra_password").(string)
	cassandraPort := d.Get("cassandra_port").(string)
	cassandraCreationStatements := d.Get("cassandra_creation_statements").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)

	/*
	 */

	body := akeyless_api.GatewayUpdateProducerCassandra{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.CassandraHosts, cassandraHosts)
	common.GetAkeylessPtr(&body.CassandraUsername, cassandraUsername)
	common.GetAkeylessPtr(&body.CassandraPassword, cassandraPassword)
	common.GetAkeylessPtr(&body.CassandraPort, cassandraPort)
	common.GetAkeylessPtr(&body.CassandraCreationStatements, cassandraCreationStatements)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)

	_, _, err = client.GatewayUpdateProducerCassandra(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerCassandraDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client

	ctx := context.Background()
	token, err := provider.getToken(ctx, d)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	path := d.Id()

	deleteItem := akeyless_api.GatewayDeleteProducer{
		Token: &token,
		Name:  path,
	}

	_, _, err = client.GatewayDeleteProducer(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceProducerCassandraImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceProducerCassandraRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
