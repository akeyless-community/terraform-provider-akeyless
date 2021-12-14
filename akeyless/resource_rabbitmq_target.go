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

func resourceRabbitmqTarget() *schema.Resource {
	return &schema.Resource{
		Description: "RabbitMQT Target resource",
		Create:      resourceRabbitmqTargetCreate,
		Read:        resourceRabbitmqTargetRead,
		Update:      resourceRabbitmqTargetUpdate,
		Delete:      resourceRabbitmqTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRabbitmqTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"rabbitmq_server_user": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "RabbitMQ server user",
			},
			"rabbitmq_server_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "RabbitMQ server password",
			},
			"rabbitmq_server_uri": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "RabbitMQ server URI",
			},
			"key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used",
			},
			"comment": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Comment about the target",
			},
		},
	}
}

func resourceRabbitmqTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	rabbitmqServerUser := d.Get("rabbitmq_server_user").(string)
	rabbitmqServerPassword := d.Get("rabbitmq_server_password").(string)
	rabbitmqServerUri := d.Get("rabbitmq_server_uri").(string)
	key := d.Get("key").(string)
	comment := d.Get("comment").(string)

	body := akeyless.CreateRabbitMQTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.RabbitmqServerUser, rabbitmqServerUser)
	common.GetAkeylessPtr(&body.RabbitmqServerUri, rabbitmqServerUri)
	common.GetAkeylessPtr(&body.RabbitmqServerPassword, rabbitmqServerPassword)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Comment, comment)

	_, _, err := client.CreateRabbitMQTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceRabbitmqTargetRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.Value.RabbitmqServerUser != nil {
		err = d.Set("rabbitmq_server_user", *rOut.Value.RabbitmqServerUser)
		if err != nil {
			return err
		}
	}
	if rOut.Value.RabbitmqServerPassword != nil {
		err = d.Set("rabbitmq_server_password", *rOut.Value.RabbitmqServerPassword)
		if err != nil {
			return err
		}
	}
	if rOut.Value.RabbitmqServerUri != nil {
		err = d.Set("rabbitmq_server_uri", *rOut.Value.RabbitmqServerUri)
		if err != nil {
			return err
		}
	}
	if rOut.Target.ProtectionKeyName != nil {
		err = d.Set("key", *rOut.Target.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.Target.Comment != nil {
		err = d.Set("comment", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceRabbitmqTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	rabbitmqServerUser := d.Get("rabbitmq_server_user").(string)
	rabbitmqServerPassword := d.Get("rabbitmq_server_password").(string)
	rabbitmqServerUri := d.Get("rabbitmq_server_uri").(string)
	key := d.Get("key").(string)
	comment := d.Get("comment").(string)

	body := akeyless.UpdateRabbitMQTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.RabbitmqServerUser, rabbitmqServerUser)
	common.GetAkeylessPtr(&body.RabbitmqServerPassword, rabbitmqServerPassword)
	common.GetAkeylessPtr(&body.RabbitmqServerUri, rabbitmqServerUri)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Comment, comment)

	_, _, err := client.UpdateRabbitMQTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceRabbitmqTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceRabbitmqTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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
