// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceProducerRabbitmq() *schema.Resource {
	return &schema.Resource{
		Description: "RabbitMQ producer resource",
		Create:      resourceProducerRabbitmqCreate,
		Read:        resourceProducerRabbitmqRead,
		Update:      resourceProducerRabbitmqUpdate,
		Delete:      resourceProducerRabbitmqDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerRabbitmqImport,
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
			"rabbitmq_server_uri": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "RabbitMQ server URI",
			},
			"rabbitmq_user_conf_permission": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "User configuration permission, for example:[.*,queue-name]",
			},
			"rabbitmq_user_write_permission": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "User write permission, for example:[.*,queue-name]",
			},
			"rabbitmq_user_read_permission": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "User read permission, for example:[.*,queue-name]",
			},
			"rabbitmq_admin_user": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "RabbitMQ server user",
			},
			"rabbitmq_admin_pwd": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "RabbitMQ server password",
			},
			"rabbitmq_user_vhost": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "User Virtual Host",
			},
			"rabbitmq_user_tags": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Comma separated list of tags to apply to user",
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
			"secure_access_enable": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_web_browsing": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Secure browser via Akeyless Web Access Bastion",
				Default:     "false",
			},
			"secure_access_url": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Destination URL to inject secrets.",
			},
		},
	}
}

func resourceProducerRabbitmqCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	rabbitmqServerUri := d.Get("rabbitmq_server_uri").(string)
	rabbitmqUserConfPermission := d.Get("rabbitmq_user_conf_permission").(string)
	rabbitmqUserWritePermission := d.Get("rabbitmq_user_write_permission").(string)
	rabbitmqUserReadPermission := d.Get("rabbitmq_user_read_permission").(string)
	rabbitmqAdminUser := d.Get("rabbitmq_admin_user").(string)
	rabbitmqAdminPwd := d.Get("rabbitmq_admin_pwd").(string)
	rabbitmqUserVhost := d.Get("rabbitmq_user_vhost").(string)
	rabbitmqUserTags := d.Get("rabbitmq_user_tags").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessUrl := d.Get("secure_access_url").(string)

	body := akeyless.GatewayCreateProducerRabbitMQ{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.RabbitmqServerUri, rabbitmqServerUri)
	common.GetAkeylessPtr(&body.RabbitmqUserConfPermission, rabbitmqUserConfPermission)
	common.GetAkeylessPtr(&body.RabbitmqUserWritePermission, rabbitmqUserWritePermission)
	common.GetAkeylessPtr(&body.RabbitmqUserReadPermission, rabbitmqUserReadPermission)
	common.GetAkeylessPtr(&body.RabbitmqAdminUser, rabbitmqAdminUser)
	common.GetAkeylessPtr(&body.RabbitmqAdminPwd, rabbitmqAdminPwd)
	common.GetAkeylessPtr(&body.RabbitmqUserVhost, rabbitmqUserVhost)
	common.GetAkeylessPtr(&body.RabbitmqUserTags, rabbitmqUserTags)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)

	_, _, err := client.GatewayCreateProducerRabbitMQ(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerRabbitmqRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.RabbitmqServerUri != nil {
		err = d.Set("rabbitmq_server_uri", *rOut.RabbitmqServerUri)
		if err != nil {
			return err
		}
	}
	if rOut.RabbitmqUserConfPermission != nil {
		err = d.Set("rabbitmq_user_conf_permission", *rOut.RabbitmqUserConfPermission)
		if err != nil {
			return err
		}
	}
	if rOut.RabbitmqUserWritePermission != nil {
		err = d.Set("rabbitmq_user_write_permission", *rOut.RabbitmqUserWritePermission)
		if err != nil {
			return err
		}
	}
	if rOut.RabbitmqUserReadPermission != nil {
		err = d.Set("rabbitmq_user_read_permission", *rOut.RabbitmqUserReadPermission)
		if err != nil {
			return err
		}
	}
	if rOut.RabbitmqUserVhost != nil {
		err = d.Set("rabbitmq_user_vhost", *rOut.RabbitmqUserVhost)
		if err != nil {
			return err
		}
	}
	if rOut.RabbitmqUserTags != nil {
		err = d.Set("rabbitmq_user_tags", *rOut.RabbitmqUserTags)
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
	if rOut.AdminName != nil {
		err = d.Set("rabbitmq_admin_user", *rOut.AdminName)
		if err != nil {
			return err
		}
	}
	if rOut.AdminPwd != nil {
		err = d.Set("rabbitmq_admin_pwd", *rOut.AdminPwd)
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

	GetRabbitMQSra(d, rOut.SecureRemoteAccessDetails)

	d.SetId(path)

	return nil
}

func resourceProducerRabbitmqUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	rabbitmqServerUri := d.Get("rabbitmq_server_uri").(string)
	rabbitmqUserConfPermission := d.Get("rabbitmq_user_conf_permission").(string)
	rabbitmqUserWritePermission := d.Get("rabbitmq_user_write_permission").(string)
	rabbitmqUserReadPermission := d.Get("rabbitmq_user_read_permission").(string)
	rabbitmqAdminUser := d.Get("rabbitmq_admin_user").(string)
	rabbitmqAdminPwd := d.Get("rabbitmq_admin_pwd").(string)
	rabbitmqUserVhost := d.Get("rabbitmq_user_vhost").(string)
	rabbitmqUserTags := d.Get("rabbitmq_user_tags").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessUrl := d.Get("secure_access_url").(string)

	body := akeyless.GatewayUpdateProducerRabbitMQ{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.RabbitmqServerUri, rabbitmqServerUri)
	common.GetAkeylessPtr(&body.RabbitmqUserConfPermission, rabbitmqUserConfPermission)
	common.GetAkeylessPtr(&body.RabbitmqUserWritePermission, rabbitmqUserWritePermission)
	common.GetAkeylessPtr(&body.RabbitmqUserReadPermission, rabbitmqUserReadPermission)
	common.GetAkeylessPtr(&body.RabbitmqAdminUser, rabbitmqAdminUser)
	common.GetAkeylessPtr(&body.RabbitmqAdminPwd, rabbitmqAdminPwd)
	common.GetAkeylessPtr(&body.RabbitmqUserVhost, rabbitmqUserVhost)
	common.GetAkeylessPtr(&body.RabbitmqUserTags, rabbitmqUserTags)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)

	_, _, err := client.GatewayUpdateProducerRabbitMQ(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerRabbitmqDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceProducerRabbitmqImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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

func GetRabbitMQSra(d *schema.ResourceData, sra *akeyless.SecureRemoteAccess) error {
	var err error
	if sra == nil {
		return nil
	}

	if _, ok := sra.GetEnableOk(); ok {
		err = d.Set("secure_access_enable", strconv.FormatBool(sra.GetEnable()))
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetUrlOk(); ok {
		err = d.Set("secure_access_url", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetIsolatedOk(); ok && *s {
		err = d.Set("secure_access_web_browsing", s)
		if err != nil {
			return err
		}
	}

	return nil
}
