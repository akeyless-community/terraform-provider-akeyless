package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretRabbitmq() *schema.Resource {
	return &schema.Resource{
		Description: "RabbitMQ dynamic secret resource",
		Create:      resourceDynamicSecretRabbitmqCreate,
		Read:        resourceDynamicSecretRabbitmqRead,
		Update:      resourceDynamicSecretRabbitmqUpdate,
		Delete:      resourceDynamicSecretRabbitmqDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretRabbitmqImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"password_length": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The length of the password to be generated",
			},
			"rabbitmq_admin_pwd": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "RabbitMQ Admin password",
			},
			"rabbitmq_admin_user": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "RabbitMQ Admin User",
			},
			"rabbitmq_server_uri": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Server URI",
			},
			"rabbitmq_user_conf_permission": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User configuration permission",
			},
			"rabbitmq_user_read_permission": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User read permission",
			},
			"rabbitmq_user_tags": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User Tags",
			},
			"rabbitmq_user_vhost": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User Virtual Host",
			},
			"rabbitmq_user_write_permission": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User write permission",
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access [true/false]",
			},
			"secure_access_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Destination URL to inject secrets",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable Web Secure Remote Access",
				Default:     true,
			},
			"secure_access_web_browsing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Secure browser via Akeyless's Secure Remote Access (SRA)",
				Default:     false,
			},
			"secure_access_web_proxy": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Web-Proxy via Akeyless's Secure Remote Access (SRA)",
				Default:     false,
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Target name",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"producer_encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Dynamic producer encryption key",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceDynamicSecretRabbitmqCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	passwordLength := d.Get("password_length").(string)
	rabbitmqAdminPwd := d.Get("rabbitmq_admin_pwd").(string)
	rabbitmqAdminUser := d.Get("rabbitmq_admin_user").(string)
	rabbitmqServerUri := d.Get("rabbitmq_server_uri").(string)
	rabbitmqUserConfPermission := d.Get("rabbitmq_user_conf_permission").(string)
	rabbitmqUserReadPermission := d.Get("rabbitmq_user_read_permission").(string)
	rabbitmqUserTags := d.Get("rabbitmq_user_tags").(string)
	rabbitmqUserVhost := d.Get("rabbitmq_user_vhost").(string)
	rabbitmqUserWritePermission := d.Get("rabbitmq_user_write_permission").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessUrl := d.Get("secure_access_url").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.DynamicSecretCreateRabbitMq{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.RabbitmqAdminPwd, rabbitmqAdminPwd)
	common.GetAkeylessPtr(&body.RabbitmqAdminUser, rabbitmqAdminUser)
	common.GetAkeylessPtr(&body.RabbitmqServerUri, rabbitmqServerUri)
	common.GetAkeylessPtr(&body.RabbitmqUserConfPermission, rabbitmqUserConfPermission)
	common.GetAkeylessPtr(&body.RabbitmqUserReadPermission, rabbitmqUserReadPermission)
	common.GetAkeylessPtr(&body.RabbitmqUserTags, rabbitmqUserTags)
	common.GetAkeylessPtr(&body.RabbitmqUserVhost, rabbitmqUserVhost)
	common.GetAkeylessPtr(&body.RabbitmqUserWritePermission, rabbitmqUserWritePermission)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.DynamicSecretCreateRabbitMq(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretRabbitmqRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get dynamic secret value", res, err)
	}

	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}
	if rOut.Tags != nil {
		err = d.Set("tags", rOut.Tags)
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

	if rOut.UserTtl != nil {
		err = d.Set("user_ttl", *rOut.UserTtl)
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

	d.SetId(path)

	return nil
}

func resourceDynamicSecretRabbitmqUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	passwordLength := d.Get("password_length").(string)
	rabbitmqAdminPwd := d.Get("rabbitmq_admin_pwd").(string)
	rabbitmqAdminUser := d.Get("rabbitmq_admin_user").(string)
	rabbitmqServerUri := d.Get("rabbitmq_server_uri").(string)
	rabbitmqUserConfPermission := d.Get("rabbitmq_user_conf_permission").(string)
	rabbitmqUserReadPermission := d.Get("rabbitmq_user_read_permission").(string)
	rabbitmqUserTags := d.Get("rabbitmq_user_tags").(string)
	rabbitmqUserVhost := d.Get("rabbitmq_user_vhost").(string)
	rabbitmqUserWritePermission := d.Get("rabbitmq_user_write_permission").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessUrl := d.Get("secure_access_url").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.DynamicSecretUpdateRabbitMq{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.RabbitmqAdminPwd, rabbitmqAdminPwd)
	common.GetAkeylessPtr(&body.RabbitmqAdminUser, rabbitmqAdminUser)
	common.GetAkeylessPtr(&body.RabbitmqServerUri, rabbitmqServerUri)
	common.GetAkeylessPtr(&body.RabbitmqUserConfPermission, rabbitmqUserConfPermission)
	common.GetAkeylessPtr(&body.RabbitmqUserReadPermission, rabbitmqUserReadPermission)
	common.GetAkeylessPtr(&body.RabbitmqUserTags, rabbitmqUserTags)
	common.GetAkeylessPtr(&body.RabbitmqUserVhost, rabbitmqUserVhost)
	common.GetAkeylessPtr(&body.RabbitmqUserWritePermission, rabbitmqUserWritePermission)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.DynamicSecretUpdateRabbitMq(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretRabbitmqDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretRabbitmqImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretRabbitmqRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
