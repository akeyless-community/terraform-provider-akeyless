// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretMongo() *schema.Resource {
	return &schema.Resource{
		Description: "Mongo DB dynamic secret resource",
		Create:      resourceDynamicSecretMongoCreate,
		Read:        resourceDynamicSecretMongoRead,
		Update:      resourceDynamicSecretMongoUpdate,
		Delete:      resourceDynamicSecretMongoDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretMongoImport,
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
			"mongodb_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB Name",
			},
			"mongodb_roles": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB Roles",
				Default:     "[]",
			},
			"mongodb_server_uri": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB server URI",
			},
			"mongodb_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB server username",
			},
			"mongodb_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "MongoDB server password. You will prompted to provide a password if it will not appear in CLI parameters",
			},
			"mongodb_host_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB server host and port",
			},
			"mongodb_default_auth_db": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB server default authentication database",
			},
			"mongodb_uri_options": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB server URI options",
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
			"mongodb_custom_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB custom data",
			},
			"mongodb_scopes": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "MongoDB Scopes (Atlas only)",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL (e.g. 60s, 60m, 60h)",
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
				Description: "Encrypt producer with following key",
			},
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customize how temporary usernames are generated using go template",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_certificate_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Secure Access",
			},
			"secure_access_bastion_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Bastion",
				Deprecated:  "use secure_access_certificate_issuer instead",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Target DB servers for connections (In case of Linked Target association, host(s) will inherit Linked Target hosts)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable Web Secure Remote Access",
			},
			"secure_access_db_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The DB name",
			},
			"secure_access_delay": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The delay duration, in seconds, to wait after generating just-in-time credentials. Accepted range: 0-120 seconds",
			},
		},
	}
}

func resourceDynamicSecretMongoCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
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
	mongodbCustomData := d.Get("mongodb_custom_data").(string)
	mongodbScopes := d.Get("mongodb_scopes").(string)
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	if secureAccessCertificateIssuer == "" {
		secureAccessCertificateIssuer = d.Get("secure_access_bastion_issuer").(string)
	}
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessDelay := d.Get("secure_access_delay").(int)

	body := akeyless_api.DynamicSecretCreateMongoDb{
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
	common.GetAkeylessPtr(&body.MongodbCustomData, mongodbCustomData)
	common.GetAkeylessPtr(&body.MongodbScopes, mongodbScopes)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ItemCustomFields, itemCustomFields)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	if secureAccessDelay != 0 {
		secureAccessDelayInt64 := int64(secureAccessDelay)
		common.GetAkeylessPtr(&body.SecureAccessDelay, secureAccessDelayInt64)
	}

	_, _, err := client.DynamicSecretCreateMongoDb(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretMongoRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
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
	if rOut.MongodbCustomData != nil {
		err = d.Set("mongodb_custom_data", *rOut.MongodbCustomData)
		if err != nil {
			return err
		}
	}
	if rOut.MongodbScopes != nil {
		err = d.Set("mongodb_scopes", *rOut.MongodbScopes)
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
	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}
	if rOut.Metadata != nil {
		err = d.Set("description", *rOut.Metadata)
		if err != nil {
			return err
		}
	}
	if rOut.ItemCustomFieldsDetails != nil && len(rOut.ItemCustomFieldsDetails) > 0 {
		customFields := make(map[string]string)
		for _, field := range rOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		if len(customFields) > 0 {
			err = d.Set("item_custom_fields", customFields)
			if err != nil {
				return err
			}
		}
	}
	if rOut.Tags != nil {
		err = d.Set("tags", rOut.Tags)
		if err != nil {
			return err
		}
	}

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = common.SetDataByPrefixSlash(d, "target_name", targetName, d.Get("target_name").(string))
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
		err = common.SetDataByPrefixSlash(d, "encryption_key_name", *rOut.DynamicSecretKey, d.Get("encryption_key_name").(string))
		if err != nil {
			return err
		}
	}

	if rOut.UsernameTemplate != nil {
		err = d.Set("custom_username_template", *rOut.UsernameTemplate)
		if err != nil {
			return err
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceDynamicSecretMongoUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
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
	mongodbCustomData := d.Get("mongodb_custom_data").(string)
	mongodbScopes := d.Get("mongodb_scopes").(string)
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	if secureAccessCertificateIssuer == "" {
		secureAccessCertificateIssuer = d.Get("secure_access_bastion_issuer").(string)
	}
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessDelay := d.Get("secure_access_delay").(int)

	body := akeyless_api.DynamicSecretUpdateMongoDb{
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
	common.GetAkeylessPtr(&body.MongodbCustomData, mongodbCustomData)
	common.GetAkeylessPtr(&body.MongodbScopes, mongodbScopes)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ItemCustomFields, itemCustomFields)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	if secureAccessDelay != 0 {
		secureAccessDelayInt64 := int64(secureAccessDelay)
		common.GetAkeylessPtr(&body.SecureAccessDelay, secureAccessDelayInt64)
	}

	_, _, err := client.DynamicSecretUpdateMongoDb(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretMongoDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretMongoImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretMongoRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
