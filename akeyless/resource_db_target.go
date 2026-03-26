// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDbTarget() *schema.Resource {
	return &schema.Resource{
		Description:        "DB Target resource",
		DeprecationMessage: "use akeyless_target_db resource instead",
		Create:             resourceDbTargetCreate,
		Read:               resourceDbTargetRead,
		Update:             resourceDbTargetUpdate,
		Delete:             resourceDbTargetDelete,
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
			"connection_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Type of connection to mssql database [credentials/cloud-identity/wallet/parent-target]",
				Default:     "credentials",
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
				Sensitive:   true,
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
				Description: "(Optional) DB server certificates",
			},
			"db_server_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "(Optional) Server name for certificate verification",
			},
			"ssl": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable/Disable SSL [true/false]",
				Default:     false,
			},
			"ssl_certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "SSL connection certificate",
			},
			"snowflake_account": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Snowflake account name",
			},
			"snowflake_api_private_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "RSA Private key (base64 encoded)",
			},
			"snowflake_api_private_key_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "The Private key passphrase",
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
				Sensitive:   true,
				Description: "MongoDB Atlas private key",
			},
			"oracle_service_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Oracle db service name",
			},
			"oracle_wallet_login_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Oracle Wallet login type (password/mtls)",
			},
			"oracle_wallet_p12_file_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Oracle wallet p12 file data in base64",
			},
			"oracle_wallet_sso_file_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Oracle wallet sso file data in base64",
			},
			"azure_client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "(Optional) Client id (relevant for \"cloud-service-provider\" only)",
			},
			"azure_client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "(Optional) Client secret (relevant for \"cloud-service-provider\" only)",
			},
			"azure_tenant_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "(Optional) Tenant id (relevant for \"cloud-service-provider\" only)",
			},
			"cloud_service_provider": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "(Optional) Cloud service provider (currently only supports Azure)",
			},
			"cluster_mode": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Cluster Mode",
			},
			"parent_target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of the parent target, relevant only when connection-type is parent-target",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of a key that used to encrypt the target secret value (if empty, the account default protectionKey key will be used)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
		},
	}
}

func resourceDbTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	dbType := d.Get("db_type").(string)
	connectionType := d.Get("connection_type").(string)
	userName := d.Get("user_name").(string)
	host := d.Get("host").(string)
	pwd := d.Get("pwd").(string)
	port := d.Get("port").(string)
	dbName := d.Get("db_name").(string)
	dbServerCertificates := d.Get("db_server_certificates").(string)
	dbServerName := d.Get("db_server_name").(string)
	ssl := d.Get("ssl").(bool)
	sslCertificate := d.Get("ssl_certificate").(string)
	snowflakeAccount := d.Get("snowflake_account").(string)
	snowflakeApiPrivateKey := d.Get("snowflake_api_private_key").(string)
	snowflakeApiPrivateKeyPassword := d.Get("snowflake_api_private_key_password").(string)
	mongodbAtlas := d.Get("mongodb_atlas").(bool)
	mongodbDefaultAuthDb := d.Get("mongodb_default_auth_db").(string)
	mongodbUriOptions := d.Get("mongodb_uri_options").(string)
	mongodbAtlasProjectId := d.Get("mongodb_atlas_project_id").(string)
	mongodbAtlasApiPublicKey := d.Get("mongodb_atlas_api_public_key").(string)
	mongodbAtlasApiPrivateKey := d.Get("mongodb_atlas_api_private_key").(string)
	oracleServiceName := d.Get("oracle_service_name").(string)
	oracleWalletLoginType := d.Get("oracle_wallet_login_type").(string)
	oracleWalletP12FileData := d.Get("oracle_wallet_p12_file_data").(string)
	oracleWalletSsoFileData := d.Get("oracle_wallet_sso_file_data").(string)
	azureClientId := d.Get("azure_client_id").(string)
	azureClientSecret := d.Get("azure_client_secret").(string)
	azureTenantId := d.Get("azure_tenant_id").(string)
	cloudServiceProvider := d.Get("cloud_service_provider").(string)
	clusterMode := d.Get("cluster_mode").(bool)
	parentTargetName := d.Get("parent_target_name").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.TargetCreateDB{
		Name:           name,
		DbType:         dbType,
		ConnectionType: connectionType,
		Token:          &token,
	}
	common.GetAkeylessPtr(&body.UserName, userName)
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.Pwd, pwd)
	common.GetAkeylessPtr(&body.Port, port)
	common.GetAkeylessPtr(&body.DbName, dbName)
	common.GetAkeylessPtr(&body.DbServerCertificates, dbServerCertificates)
	common.GetAkeylessPtr(&body.DbServerName, dbServerName)
	common.GetAkeylessPtr(&body.Ssl, ssl)
	common.GetAkeylessPtr(&body.SslCertificate, sslCertificate)
	common.GetAkeylessPtr(&body.SnowflakeAccount, snowflakeAccount)
	common.GetAkeylessPtr(&body.SnowflakeApiPrivateKey, snowflakeApiPrivateKey)
	common.GetAkeylessPtr(&body.SnowflakeApiPrivateKeyPassword, snowflakeApiPrivateKeyPassword)
	common.GetAkeylessPtr(&body.MongodbAtlas, mongodbAtlas)
	common.GetAkeylessPtr(&body.MongodbDefaultAuthDb, mongodbDefaultAuthDb)
	common.GetAkeylessPtr(&body.MongodbUriOptions, mongodbUriOptions)
	common.GetAkeylessPtr(&body.MongodbAtlasProjectId, mongodbAtlasProjectId)
	common.GetAkeylessPtr(&body.MongodbAtlasApiPublicKey, mongodbAtlasApiPublicKey)
	common.GetAkeylessPtr(&body.MongodbAtlasApiPrivateKey, mongodbAtlasApiPrivateKey)
	common.GetAkeylessPtr(&body.OracleServiceName, oracleServiceName)
	common.GetAkeylessPtr(&body.OracleWalletLoginType, oracleWalletLoginType)
	common.GetAkeylessPtr(&body.OracleWalletP12FileData, oracleWalletP12FileData)
	common.GetAkeylessPtr(&body.OracleWalletSsoFileData, oracleWalletSsoFileData)
	common.GetAkeylessPtr(&body.AzureClientId, azureClientId)
	common.GetAkeylessPtr(&body.AzureClientSecret, azureClientSecret)
	common.GetAkeylessPtr(&body.AzureTenantId, azureTenantId)
	common.GetAkeylessPtr(&body.CloudServiceProvider, cloudServiceProvider)
	common.GetAkeylessPtr(&body.ClusterMode, clusterMode)
	common.GetAkeylessPtr(&body.ParentTargetName, parentTargetName)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.TargetCreateDB(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDbTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
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

	targetType, err := getTargetType(rOut.Target)
	if err != nil {
		return err
	}

	if rOut.Value.DbTargetDetails != nil {
		dbTargetDetails := *rOut.Value.DbTargetDetails
		if dbTargetDetails.ConnectionType != nil {
			err := d.Set("connection_type", *dbTargetDetails.ConnectionType)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.DbHostName != nil {
			err := d.Set("host", *dbTargetDetails.DbHostName)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.DbPort != nil {
			err := d.Set("port", *dbTargetDetails.DbPort)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.DbUserName != nil {
			err := d.Set("user_name", *dbTargetDetails.DbUserName)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.DbPwd != nil {
			err := d.Set("pwd", *dbTargetDetails.DbPwd)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.DbName != nil {
			// oracle_service_name can be extracted from DbName
			if targetType == "oracle" {
				err := d.Set("oracle_service_name", *dbTargetDetails.DbName)
				if err != nil {
					return err
				}
			} else {
				err := d.Set("db_name", *dbTargetDetails.DbName)
				if err != nil {
					return err
				}
			}
		}
		if dbTargetDetails.DbServerCertificates != nil {
			err := d.Set("db_server_certificates", *dbTargetDetails.DbServerCertificates)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.DbServerName != nil {
			err := d.Set("db_server_name", *dbTargetDetails.DbServerName)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.SslConnectionMode != nil {
			err = d.Set("ssl", *dbTargetDetails.SslConnectionMode)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.SslConnectionCertificate != nil {
			err = d.Set("ssl_certificate", *dbTargetDetails.SslConnectionCertificate)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.SfAccount != nil {
			err := d.Set("snowflake_account", *dbTargetDetails.SfAccount)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.DbPrivateKey != nil {
			err := d.Set("snowflake_api_private_key", *dbTargetDetails.DbPrivateKey)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.DbPrivateKeyPassphrase != nil {
			err := d.Set("snowflake_api_private_key_password", *dbTargetDetails.DbPrivateKeyPassphrase)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.DbClientId != nil {
			err := d.Set("azure_client_id", *dbTargetDetails.DbClientId)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.DbClientSecret != nil {
			err := d.Set("azure_client_secret", *dbTargetDetails.DbClientSecret)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.DbTenantId != nil {
			err := d.Set("azure_tenant_id", *dbTargetDetails.DbTenantId)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.CloudServiceProvider != nil {
			err := d.Set("cloud_service_provider", *dbTargetDetails.CloudServiceProvider)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.ClusterMode != nil {
			err := d.Set("cluster_mode", *dbTargetDetails.ClusterMode)
			if err != nil {
				return err
			}
		}
		if dbTargetDetails.OracleWalletDetails != nil {
			walletDetails := *dbTargetDetails.OracleWalletDetails
			if walletDetails.LoginType != nil {
				err := d.Set("oracle_wallet_login_type", *walletDetails.LoginType)
				if err != nil {
					return err
				}
			}
			if walletDetails.P12DataBase64 != nil {
				err := d.Set("oracle_wallet_p12_file_data", *walletDetails.P12DataBase64)
				if err != nil {
					return err
				}
			}
			if walletDetails.SsoDataBase64 != nil {
				err := d.Set("oracle_wallet_sso_file_data", *walletDetails.SsoDataBase64)
				if err != nil {
					return err
				}
			}
		}
	}
	if rOut.Target.ParentTargetName != nil {
		err := d.Set("parent_target_name", *rOut.Target.ParentTargetName)
		if err != nil {
			return err
		}
	}
	if rOut.Value.MongoDbTargetDetails != nil {
		mongoDetails := *rOut.Value.MongoDbTargetDetails
		if mongoDetails.MongodbIsAtlas != nil {
			err := d.Set("mongodb_atlas", *mongoDetails.MongodbIsAtlas)
			if err != nil {
				return err
			}
		}
		if mongoDetails.MongodbDefaultAuthDb != nil {
			err := d.Set("mongodb_default_auth_db", *mongoDetails.MongodbDefaultAuthDb)
			if err != nil {
				return err
			}
		}
		if mongoDetails.MongodbUriOptions != nil {
			err := d.Set("mongodb_uri_options", *mongoDetails.MongodbUriOptions)
			if err != nil {
				return err
			}
		}
		if mongoDetails.MongodbAtlasProjectId != nil {
			err := d.Set("mongodb_atlas_project_id", *mongoDetails.MongodbAtlasProjectId)
			if err != nil {
				return err
			}
		}
		if mongoDetails.MongodbAtlasApiPublicKey != nil {
			err := d.Set("mongodb_atlas_api_public_key", *mongoDetails.MongodbAtlasApiPublicKey)
			if err != nil {
				return err
			}
		}
		if mongoDetails.MongodbAtlasApiPrivateKey != nil {
			err := d.Set("mongodb_atlas_api_private_key", *mongoDetails.MongodbAtlasApiPrivateKey)
			if err != nil {
				return err
			}
		}
	}
	if rOut.Target.ProtectionKeyName != nil {
		err := common.SetDataByPrefixSlash(d, "key", *rOut.Target.ProtectionKeyName, d.Get("key").(string))
		if err != nil {
			return err
		}
	}

	if rOut.Target.Comment != nil {
		err := d.Set("description", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceDbTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	dbType := d.Get("db_type").(string)
	connectionType := d.Get("connection_type").(string)
	userName := d.Get("user_name").(string)
	host := d.Get("host").(string)
	pwd := d.Get("pwd").(string)
	port := d.Get("port").(string)
	dbName := d.Get("db_name").(string)
	dbServerCertificates := d.Get("db_server_certificates").(string)
	dbServerName := d.Get("db_server_name").(string)
	ssl := d.Get("ssl").(bool)
	sslCertificate := d.Get("ssl_certificate").(string)
	snowflakeAccount := d.Get("snowflake_account").(string)
	snowflakeApiPrivateKey := d.Get("snowflake_api_private_key").(string)
	snowflakeApiPrivateKeyPassword := d.Get("snowflake_api_private_key_password").(string)
	mongodbAtlas := d.Get("mongodb_atlas").(bool)
	mongodbDefaultAuthDb := d.Get("mongodb_default_auth_db").(string)
	mongodbUriOptions := d.Get("mongodb_uri_options").(string)
	mongodbAtlasProjectId := d.Get("mongodb_atlas_project_id").(string)
	mongodbAtlasApiPublicKey := d.Get("mongodb_atlas_api_public_key").(string)
	mongodbAtlasApiPrivateKey := d.Get("mongodb_atlas_api_private_key").(string)
	oracleServiceName := d.Get("oracle_service_name").(string)
	oracleWalletLoginType := d.Get("oracle_wallet_login_type").(string)
	oracleWalletP12FileData := d.Get("oracle_wallet_p12_file_data").(string)
	oracleWalletSsoFileData := d.Get("oracle_wallet_sso_file_data").(string)
	azureClientId := d.Get("azure_client_id").(string)
	azureClientSecret := d.Get("azure_client_secret").(string)
	azureTenantId := d.Get("azure_tenant_id").(string)
	cloudServiceProvider := d.Get("cloud_service_provider").(string)
	clusterMode := d.Get("cluster_mode").(bool)
	parentTargetName := d.Get("parent_target_name").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.TargetUpdateDB{
		Name:           name,
		DbType:         dbType,
		ConnectionType: connectionType,
		Token:          &token,
	}
	common.GetAkeylessPtr(&body.UserName, userName)
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.Pwd, pwd)
	common.GetAkeylessPtr(&body.Port, port)
	common.GetAkeylessPtr(&body.DbName, dbName)
	common.GetAkeylessPtr(&body.DbServerCertificates, dbServerCertificates)
	common.GetAkeylessPtr(&body.DbServerName, dbServerName)
	common.GetAkeylessPtr(&body.Ssl, ssl)
	common.GetAkeylessPtr(&body.SslCertificate, sslCertificate)
	common.GetAkeylessPtr(&body.SnowflakeAccount, snowflakeAccount)
	common.GetAkeylessPtr(&body.SnowflakeApiPrivateKey, snowflakeApiPrivateKey)
	common.GetAkeylessPtr(&body.SnowflakeApiPrivateKeyPassword, snowflakeApiPrivateKeyPassword)
	common.GetAkeylessPtr(&body.MongodbAtlas, mongodbAtlas)
	common.GetAkeylessPtr(&body.MongodbDefaultAuthDb, mongodbDefaultAuthDb)
	common.GetAkeylessPtr(&body.MongodbUriOptions, mongodbUriOptions)
	common.GetAkeylessPtr(&body.MongodbAtlasProjectId, mongodbAtlasProjectId)
	common.GetAkeylessPtr(&body.MongodbAtlasApiPublicKey, mongodbAtlasApiPublicKey)
	common.GetAkeylessPtr(&body.MongodbAtlasApiPrivateKey, mongodbAtlasApiPrivateKey)
	common.GetAkeylessPtr(&body.OracleServiceName, oracleServiceName)
	common.GetAkeylessPtr(&body.OracleWalletLoginType, oracleWalletLoginType)
	common.GetAkeylessPtr(&body.OracleWalletP12FileData, oracleWalletP12FileData)
	common.GetAkeylessPtr(&body.OracleWalletSsoFileData, oracleWalletSsoFileData)
	common.GetAkeylessPtr(&body.AzureClientId, azureClientId)
	common.GetAkeylessPtr(&body.AzureClientSecret, azureClientSecret)
	common.GetAkeylessPtr(&body.AzureTenantId, azureTenantId)
	common.GetAkeylessPtr(&body.CloudServiceProvider, cloudServiceProvider)
	common.GetAkeylessPtr(&body.ClusterMode, clusterMode)
	common.GetAkeylessPtr(&body.ParentTargetName, parentTargetName)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.TargetUpdateDB(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update ", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDbTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.TargetDelete{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.TargetDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceDbTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDbTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
