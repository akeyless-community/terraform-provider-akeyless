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

func resourceDynamicSecretCassandra() *schema.Resource {
	return &schema.Resource{
		Description: "Cassandra producer resource",
		Create:      resourceDynamicSecretCassandraCreate,
		Read:        resourceDynamicSecretCassandraRead,
		Update:      resourceDynamicSecretCassandraUpdate,
		Delete:      resourceDynamicSecretCassandraDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretCassandraImport,
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
			"cassandra_hosts": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Cassandra hosts names or IP addresses, comma separated",
			},
			"cassandra_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Cassandra superuser user name",
			},
			"cassandra_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Cassandra superuser password",
			},
			"cassandra_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Cassandra port",
				Default:     "9042",
			},
			"cassandra_creation_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Cassandra Creation Statements",
				Default:     "CREATE ROLE '{{username}}' WITH PASSWORD = '{{password}}' AND LOGIN = true; GRANT SELECT ON ALL KEYSPACES TO '{{username}}';",
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
				Description: "User TTL (<=60m for access token)",
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
		},
	}
}

func resourceDynamicSecretCassandraCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	cassandraHosts := d.Get("cassandra_hosts").(string)
	cassandraUsername := d.Get("cassandra_username").(string)
	cassandraPassword := d.Get("cassandra_password").(string)
	cassandraPort := d.Get("cassandra_port").(string)
	creationStatements := d.Get("cassandra_creation_statements").(string)
	ssl := d.Get("ssl").(bool)
	sslCertificate := d.Get("ssl_certificate").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)

	body := akeyless.DynamicSecretCreateCassandra{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.CassandraHosts, cassandraHosts)
	common.GetAkeylessPtr(&body.CassandraUsername, cassandraUsername)
	common.GetAkeylessPtr(&body.CassandraPassword, cassandraPassword)
	common.GetAkeylessPtr(&body.CassandraPort, cassandraPort)
	common.GetAkeylessPtr(&body.CassandraCreationStatements, creationStatements)
	common.GetAkeylessPtr(&body.Ssl, ssl)
	common.GetAkeylessPtr(&body.SslCertificate, sslCertificate)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.Tags, tags)

	_, _, err := client.DynamicSecretCreateCassandra(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretCassandraRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.CassandraCreationStatements != nil {
		err = d.Set("cassandra_creation_statements", *rOut.CassandraCreationStatements)
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
		err = d.Set("encryption_key_name", *rOut.DynamicSecretKey)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceDynamicSecretCassandraUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	cassandraHosts := d.Get("cassandra_hosts").(string)
	cassandraUsername := d.Get("cassandra_username").(string)
	cassandraPassword := d.Get("cassandra_password").(string)
	cassandraPort := d.Get("cassandra_port").(string)
	creationStatements := d.Get("cassandra_creation_statements").(string)
	ssl := d.Get("ssl").(bool)
	sslCertificate := d.Get("ssl_certificate").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)

	body := akeyless.DynamicSecretUpdateCassandra{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.CassandraHosts, cassandraHosts)
	common.GetAkeylessPtr(&body.CassandraUsername, cassandraUsername)
	common.GetAkeylessPtr(&body.CassandraPassword, cassandraPassword)
	common.GetAkeylessPtr(&body.CassandraPort, cassandraPort)
	common.GetAkeylessPtr(&body.CassandraCreationStatements, creationStatements)
	common.GetAkeylessPtr(&body.Ssl, ssl)
	common.GetAkeylessPtr(&body.SslCertificate, sslCertificate)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.Tags, tags)

	_, _, err := client.DynamicSecretUpdateCassandra(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretCassandraDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretCassandraImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretCassandraRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
