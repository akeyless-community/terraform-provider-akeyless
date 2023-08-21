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

func resourceDbTarget() *schema.Resource {
	return &schema.Resource{
		Description: "DB Target resource",
		Create:      resourceDbTargetCreate,
		Read:        resourceDbTargetRead,
		Update:      resourceDbTargetUpdate,
		Delete:      resourceDbTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDbTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"db_type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Database type: mysql/mssql/postgres/mongodb/snowflake/oracle/cassandra/redshift",
			},
			"user_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Database user name",
			},
			"host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Database host",
			},
			"pwd": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Database password",
			},
			"port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Database port",
			},
			"db_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Database name",
			},
			"db_server_certificates": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set of root certificate authorities in base64 encoding used by clients to verify server certificates",
			},
			"db_server_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Server name is used to verify the hostname on the returned certificates unless InsecureSkipVerify is provided. It is also included in the client's handshake to support virtual hosting unless it is an IP address",
			},
			"snowflake_account": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Snowflake account name",
			},
			"mongodb_atlas": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Flag, set database type to mongodb and the flag to true to create Mongo Atlas target",
			},
			"mongodb_default_auth_db": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB server default authentication database",
			},
			"mongodb_uri_options": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB server URI options (e.g. replicaSet=mySet&authSource=authDB)",
			},
			"mongodb_atlas_project_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB Atlas project ID",
			},
			"mongodb_atlas_api_public_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB Atlas public key",
			},
			"mongodb_atlas_api_private_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB Atlas private key",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used",
			},
			"comment": {
				Type:       schema.TypeString,
				Optional:   true,
				Deprecated: "Deprecated: Use description instead",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"oracle_service_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "oracle db service name",
			},
		},
	}
}

func resourceDbTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	dbType := d.Get("db_type").(string)
	userName := d.Get("user_name").(string)
	host := d.Get("host").(string)
	pwd := d.Get("pwd").(string)
	port := d.Get("port").(string)
	dbName := d.Get("db_name").(string)
	dbServerCertificates := d.Get("db_server_certificates").(string)
	dbServerName := d.Get("db_server_name").(string)
	snowflakeAccount := d.Get("snowflake_account").(string)
	mongodbAtlas := d.Get("mongodb_atlas").(bool)
	mongodbDefaultAuthDb := d.Get("mongodb_default_auth_db").(string)
	mongodbUriOptions := d.Get("mongodb_uri_options").(string)
	mongodbAtlasProjectId := d.Get("mongodb_atlas_project_id").(string)
	mongodbAtlasApiPublicKey := d.Get("mongodb_atlas_api_public_key").(string)
	mongodbAtlasApiPrivateKey := d.Get("mongodb_atlas_api_private_key").(string)
	key := d.Get("key").(string)
	comment := d.Get("comment").(string)
	description := d.Get("description").(string)
	oracleServiceName := d.Get("oracle_service_name").(string)

	body := akeyless.CreateDBTarget{
		Name:   name,
		DbType: dbType,
		Token:  &token,
	}
	common.GetAkeylessPtr(&body.UserName, userName)
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.Pwd, pwd)
	common.GetAkeylessPtr(&body.Port, port)
	common.GetAkeylessPtr(&body.DbName, dbName)
	common.GetAkeylessPtr(&body.DbServerCertificates, dbServerCertificates)
	common.GetAkeylessPtr(&body.DbServerName, dbServerName)
	common.GetAkeylessPtr(&body.SnowflakeAccount, snowflakeAccount)
	common.GetAkeylessPtr(&body.MongodbAtlas, mongodbAtlas)
	common.GetAkeylessPtr(&body.MongodbDefaultAuthDb, mongodbDefaultAuthDb)
	common.GetAkeylessPtr(&body.MongodbUriOptions, mongodbUriOptions)
	common.GetAkeylessPtr(&body.MongodbAtlasProjectId, mongodbAtlasProjectId)
	common.GetAkeylessPtr(&body.MongodbAtlasApiPublicKey, mongodbAtlasApiPublicKey)
	common.GetAkeylessPtr(&body.MongodbAtlasApiPrivateKey, mongodbAtlasApiPrivateKey)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Comment, comment)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.OracleServiceName, oracleServiceName)

	_, _, err := client.CreateDBTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDbTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GetTargetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GetTargetDetails(ctx).Body(body).Execute()
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
	if rOut.Value.DbTargetDetails != nil {
		if rOut.Value.DbTargetDetails.DbHostName != nil {
			err := d.Set("host", *rOut.Value.DbTargetDetails.DbHostName)
			if err != nil {
				return err
			}
		}
		if rOut.Value.DbTargetDetails.DbPort != nil {
			err := d.Set("port", *rOut.Value.DbTargetDetails.DbPort)
			if err != nil {
				return err
			}
		}
		if rOut.Value.DbTargetDetails.DbUserName != nil {
			err := d.Set("user_name", *rOut.Value.DbTargetDetails.DbUserName)
			if err != nil {
				return err
			}
		}
		if rOut.Value.DbTargetDetails.DbPwd != nil {
			err := d.Set("pwd", *rOut.Value.DbTargetDetails.DbPwd)
			if err != nil {
				return err
			}
		}
		if rOut.Value.DbTargetDetails.DbName != nil {
			// oracle_service_name can be extracted from DbName in the result
			if d.Get("db_type") == "oracle" {
				err := d.Set("oracle_service_name", *rOut.Value.DbTargetDetails.DbName)
				if err != nil {
					return err
				}
			} else {
				err := d.Set("db_name", *rOut.Value.DbTargetDetails.DbName)
				if err != nil {
					return err
				}
			}
		}
		if rOut.Value.DbTargetDetails.DbServerCertificates != nil {
			err := d.Set("db_server_certificates", *rOut.Value.DbTargetDetails.DbServerCertificates)
			if err != nil {
				return err
			}
		}
		if rOut.Value.DbTargetDetails.DbServerName != nil {
			err := d.Set("db_server_name", *rOut.Value.DbTargetDetails.DbServerName)
			if err != nil {
				return err
			}
		}
		if rOut.Value.DbTargetDetails.SfAccount != nil {
			err := d.Set("snowflake_account", *rOut.Value.DbTargetDetails.SfAccount)
			if err != nil {
				return err
			}
		}
	}
	if rOut.Value.MongoDbTargetDetails != nil {
		if rOut.Value.MongoDbTargetDetails.MongodbIsAtlas != nil {
			err := d.Set("mongodb_atlas", *rOut.Value.MongoDbTargetDetails.MongodbIsAtlas)
			if err != nil {
				return err
			}
		}
		if rOut.Value.MongoDbTargetDetails.MongodbDefaultAuthDb != nil {
			err := d.Set("mongodb_default_auth_db", *rOut.Value.MongoDbTargetDetails.MongodbDefaultAuthDb)
			if err != nil {
				return err
			}
		}
		if rOut.Value.MongoDbTargetDetails.MongodbUriOptions != nil {
			err := d.Set("mongodb_uri_options", *rOut.Value.MongoDbTargetDetails.MongodbUriOptions)
			if err != nil {
				return err
			}
		}
		if rOut.Value.MongoDbTargetDetails.MongodbAtlasProjectId != nil {
			err := d.Set("mongodb_atlas_project_id", *rOut.Value.MongoDbTargetDetails.MongodbAtlasProjectId)
			if err != nil {
				return err
			}
		}
		if rOut.Value.MongoDbTargetDetails.MongodbAtlasApiPublicKey != nil {
			err := d.Set("mongodb_atlas_api_public_key", *rOut.Value.MongoDbTargetDetails.MongodbAtlasApiPublicKey)
			if err != nil {
				return err
			}
		}
		if rOut.Value.MongoDbTargetDetails.MongodbAtlasApiPrivateKey != nil {
			err := d.Set("mongodb_atlas_api_private_key", *rOut.Value.MongoDbTargetDetails.MongodbAtlasApiPrivateKey)
			if err != nil {
				return err
			}
		}
	}
	if rOut.Target.ProtectionKeyName != nil {
		err := d.Set("key", *rOut.Target.ProtectionKeyName)
		if err != nil {
			return err
		}
	}

	if rOut.Target.Comment != nil {
		err := common.SetDescriptionBc(d, *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceDbTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	dbType := d.Get("db_type").(string)
	userName := d.Get("user_name").(string)
	host := d.Get("host").(string)
	pwd := d.Get("pwd").(string)
	port := d.Get("port").(string)
	dbName := d.Get("db_name").(string)
	dbServerCertificates := d.Get("db_server_certificates").(string)
	dbServerName := d.Get("db_server_name").(string)
	snowflakeAccount := d.Get("snowflake_account").(string)
	mongodbAtlas := d.Get("mongodb_atlas").(bool)
	mongodbDefaultAuthDb := d.Get("mongodb_default_auth_db").(string)
	mongodbUriOptions := d.Get("mongodb_uri_options").(string)
	mongodbAtlasProjectId := d.Get("mongodb_atlas_project_id").(string)
	mongodbAtlasApiPublicKey := d.Get("mongodb_atlas_api_public_key").(string)
	mongodbAtlasApiPrivateKey := d.Get("mongodb_atlas_api_private_key").(string)
	key := d.Get("key").(string)
	comment := d.Get("comment").(string)
	description := d.Get("description").(string)
	oracleServiceName := d.Get("oracle_service_name").(string)

	body := akeyless.UpdateDBTarget{
		Name:   name,
		DbType: dbType,
		Token:  &token,
	}
	common.GetAkeylessPtr(&body.UserName, userName)
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.Pwd, pwd)
	common.GetAkeylessPtr(&body.Port, port)
	common.GetAkeylessPtr(&body.DbName, dbName)
	common.GetAkeylessPtr(&body.DbServerCertificates, dbServerCertificates)
	common.GetAkeylessPtr(&body.DbServerName, dbServerName)
	common.GetAkeylessPtr(&body.SnowflakeAccount, snowflakeAccount)
	common.GetAkeylessPtr(&body.MongodbAtlas, mongodbAtlas)
	common.GetAkeylessPtr(&body.MongodbDefaultAuthDb, mongodbDefaultAuthDb)
	common.GetAkeylessPtr(&body.MongodbUriOptions, mongodbUriOptions)
	common.GetAkeylessPtr(&body.MongodbAtlasProjectId, mongodbAtlasProjectId)
	common.GetAkeylessPtr(&body.MongodbAtlasApiPublicKey, mongodbAtlasApiPublicKey)
	common.GetAkeylessPtr(&body.MongodbAtlasApiPrivateKey, mongodbAtlasApiPrivateKey)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Comment, comment)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.OracleServiceName, oracleServiceName)

	_, _, err := client.UpdateDBTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDbTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteTarget{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteTarget(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceDbTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GetTarget{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GetTarget(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
