// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceProducerMongo() *schema.Resource {
	return &schema.Resource{
		Description: "Mongo DB Producer resource",
		Create:      resourceProducerMongoCreate,
		Read:        resourceProducerMongoRead,
		Update:      resourceProducerMongoUpdate,
		Delete:      resourceProducerMongoDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerMongoImport,
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
			"mongodb_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MongoDB name",
			},
			"mongodb_roles": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MongoDB roles (e.g. MongoDB:[{role:readWrite, db: sales}], MongoDB Atlas:[{roleName : readWrite, databaseName: sales}])",
				Default:     "[]",
			},
			"mongodb_server_uri": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MongoDB server URI (e.g. mongodb://user:password@my.mongo.db:27017/admin?replicaSet=mySet)",
			},
			"mongodb_username": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MongoDB server username",
			},
			"mongodb_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MongoDB server password",
			},
			"mongodb_host_port": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "host:port (e.g. my.mongo.db:27017)",
			},
			"mongodb_default_auth_db": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MongoDB server default authentication database",
			},
			"mongodb_uri_options": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MongoDB server URI options (e.g. replicaSet=mySet&authSource=authDB)",
			},
			"mongodb_atlas_project_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MongoDB Atlas project ID",
			},
			"mongodb_atlas_api_public_key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MongoDB Atlas public key",
			},
			"mongodb_atlas_api_private_key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "MongoDB Atlas private key",
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
				Description: "User TTL (e.g. 60s, 60m, 60h)",
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

func resourceProducerMongoCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	mongodbName := d.Get("mongodb_name").(string)
	mongodbRoles := d.Get("mongodb_roles").(string)
	mongodbServerUri := d.Get("mongodb_server_uri").(string)
	mongodbUsername := d.Get("mongodb_username").(string)
	mongodbPassword := d.Get("mongodb_password").(string)
	mongodbHostPort := d.Get("mongodb_host_port").(string)
	mongodbDefaultAuthDb := d.Get("mongodb_default_auth_db").(string)
	mongodbUriOptions := d.Get("mongodb_uri_options").(string)
	mongodbAtlasProjectId := d.Get("mongodb_atlas_project_id").(string)
	mongodbAtlasApiPublicKey := d.Get("mongodb_atlas_api_public_key").(string)
	mongodbAtlasApiPrivateKey := d.Get("mongodb_atlas_api_private_key").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.GatewayCreateProducerMongo{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.MongodbName, mongodbName)
	common.GetAkeylessPtr(&body.MongodbRoles, mongodbRoles)
	common.GetAkeylessPtr(&body.MongodbServerUri, mongodbServerUri)
	common.GetAkeylessPtr(&body.MongodbUsername, mongodbUsername)
	common.GetAkeylessPtr(&body.MongodbPassword, mongodbPassword)
	common.GetAkeylessPtr(&body.MongodbHostPort, mongodbHostPort)
	common.GetAkeylessPtr(&body.MongodbDefaultAuthDb, mongodbDefaultAuthDb)
	common.GetAkeylessPtr(&body.MongodbUriOptions, mongodbUriOptions)
	common.GetAkeylessPtr(&body.MongodbAtlasProjectId, mongodbAtlasProjectId)
	common.GetAkeylessPtr(&body.MongodbAtlasApiPublicKey, mongodbAtlasApiPublicKey)
	common.GetAkeylessPtr(&body.MongodbAtlasApiPrivateKey, mongodbAtlasApiPrivateKey)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.GatewayCreateProducerMongo(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerMongoRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.MongodbRoles != nil {
		err = d.Set("mongodb_roles", *rOut.MongodbRoles)
		if err != nil {
			return err
		}
	}
	if rOut.MongodbUsername != nil {
		err = d.Set("mongodb_username", *rOut.MongodbUsername)
		if err != nil {
			return err
		}
	}
	if rOut.MongodbPassword != nil {
		err = d.Set("mongodb_password", *rOut.MongodbPassword)
		if err != nil {
			return err
		}
	}
	if rOut.MongodbHostPort != nil {
		err = d.Set("mongodb_host_port", *rOut.MongodbHostPort)
		if err != nil {
			return err
		}
	}
	if rOut.MongodbDefaultAuthDb != nil {
		err = d.Set("mongodb_default_auth_db", *rOut.MongodbDefaultAuthDb)
		if err != nil {
			return err
		}
	}
	if rOut.MongodbUriOptions != nil {
		err = d.Set("mongodb_uri_options", *rOut.MongodbUriOptions)
		if err != nil {
			return err
		}
	}
	if rOut.MongodbAtlasProjectId != nil {
		err = d.Set("mongodb_atlas_project_id", *rOut.MongodbAtlasProjectId)
		if err != nil {
			return err
		}
	}
	if rOut.MongodbAtlasApiPublicKey != nil {
		err = d.Set("mongodb_atlas_api_public_key", *rOut.MongodbAtlasApiPublicKey)
		if err != nil {
			return err
		}
	}
	if rOut.MongodbAtlasApiPrivateKey != nil {
		err = d.Set("mongodb_atlas_api_private_key", *rOut.MongodbAtlasApiPrivateKey)
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

	if rOut.MongodbDbName != nil {
		err = d.Set("mongodb_name", *rOut.MongodbDbName)
		if err != nil {
			return err
		}
	}
	if rOut.MongodbUriConnection != nil {
		err = d.Set("mongodb_server_uri", *rOut.MongodbUriConnection)
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

func resourceProducerMongoUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	mongodbName := d.Get("mongodb_name").(string)
	mongodbRoles := d.Get("mongodb_roles").(string)
	mongodbServerUri := d.Get("mongodb_server_uri").(string)
	mongodbUsername := d.Get("mongodb_username").(string)
	mongodbPassword := d.Get("mongodb_password").(string)
	mongodbHostPort := d.Get("mongodb_host_port").(string)
	mongodbDefaultAuthDb := d.Get("mongodb_default_auth_db").(string)
	mongodbUriOptions := d.Get("mongodb_uri_options").(string)
	mongodbAtlasProjectId := d.Get("mongodb_atlas_project_id").(string)
	mongodbAtlasApiPublicKey := d.Get("mongodb_atlas_api_public_key").(string)
	mongodbAtlasApiPrivateKey := d.Get("mongodb_atlas_api_private_key").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.GatewayUpdateProducerMongo{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.MongodbName, mongodbName)
	common.GetAkeylessPtr(&body.MongodbRoles, mongodbRoles)
	common.GetAkeylessPtr(&body.MongodbServerUri, mongodbServerUri)
	common.GetAkeylessPtr(&body.MongodbUsername, mongodbUsername)
	common.GetAkeylessPtr(&body.MongodbPassword, mongodbPassword)
	common.GetAkeylessPtr(&body.MongodbHostPort, mongodbHostPort)
	common.GetAkeylessPtr(&body.MongodbDefaultAuthDb, mongodbDefaultAuthDb)
	common.GetAkeylessPtr(&body.MongodbUriOptions, mongodbUriOptions)
	common.GetAkeylessPtr(&body.MongodbAtlasProjectId, mongodbAtlasProjectId)
	common.GetAkeylessPtr(&body.MongodbAtlasApiPublicKey, mongodbAtlasApiPublicKey)
	common.GetAkeylessPtr(&body.MongodbAtlasApiPrivateKey, mongodbAtlasApiPrivateKey)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.GatewayUpdateProducerMongo(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerMongoDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceProducerMongoImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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
