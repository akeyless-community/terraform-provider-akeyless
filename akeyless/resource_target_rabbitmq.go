// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
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
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("rabbitmq_server_password"), cty.GetAttrPath("rabbitmq_server_password_wo")),
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
			"rabbitmq_server_password_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "rabbitmq_server_password (write-only, not stored in state). Requires Terraform 1.11+. Bump rabbitmq_server_password_wo_version to change it.",
			},
			"rabbitmq_server_password_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for rabbitmq_server_password_wo. Increment to update the value.",
			},
			"rabbitmq_server_uri": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "RabbitMQ server URI",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
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
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceRabbitmqTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	rabbitmqServerUser := d.Get("rabbitmq_server_user").(string)
	rabbitmqServerPassword, err := common.EffectiveSecretValue(d, "rabbitmq_server_password", "rabbitmq_server_password_wo")
	if err != nil {
		return err
	}
	rabbitmqServerUri := d.Get("rabbitmq_server_uri").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.TargetCreateRabbitMq{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.RabbitmqServerUser, rabbitmqServerUser)
	common.GetAkeylessPtr(&body.RabbitmqServerUri, rabbitmqServerUri)
	common.GetAkeylessPtr(&body.RabbitmqServerPassword, rabbitmqServerPassword)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.TargetCreateRabbitMq(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRabbitmqTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get target details", res, err)
	}

	if rOut.Value != nil && rOut.Value.RabbitMqTargetDetails != nil && rOut.Value.RabbitMqTargetDetails.RabbitmqServerUser != nil {
		err = d.Set("rabbitmq_server_user", *rOut.Value.RabbitMqTargetDetails.RabbitmqServerUser)
		if err != nil {
			return err
		}
	}
	if rOut.Value != nil && rOut.Value.RabbitMqTargetDetails != nil && rOut.Value.RabbitMqTargetDetails.RabbitmqServerPassword != nil {
		err = common.SetSecretFromRead(d, "rabbitmq_server_password", "rabbitmq_server_password_wo", "rabbitmq_server_password_wo_version", *rOut.Value.RabbitMqTargetDetails.RabbitmqServerPassword)
		if err != nil {
			return err
		}
	}
	if rOut.Value != nil && rOut.Value.RabbitMqTargetDetails != nil && rOut.Value.RabbitMqTargetDetails.RabbitmqServerUri != nil {
		err = d.Set("rabbitmq_server_uri", *rOut.Value.RabbitMqTargetDetails.RabbitmqServerUri)
		if err != nil {
			return err
		}
	}
	if rOut.Target != nil && rOut.Target.ProtectionKeyName != nil {
		err = d.Set("key", *rOut.Target.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.Target != nil && rOut.Target.Comment != nil {
		err := d.Set("description", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceRabbitmqTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	rabbitmqServerUser := d.Get("rabbitmq_server_user").(string)
	rabbitmqServerPassword, err := common.EffectiveSecretValue(d, "rabbitmq_server_password", "rabbitmq_server_password_wo")
	if err != nil {
		return err
	}
	rabbitmqServerUri := d.Get("rabbitmq_server_uri").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.TargetUpdateRabbitMq{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.RabbitmqServerUser, rabbitmqServerUser)
	common.GetAkeylessPtr(&body.RabbitmqServerPassword, rabbitmqServerPassword)
	common.GetAkeylessPtr(&body.RabbitmqServerUri, rabbitmqServerUri)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.TargetUpdateRabbitMq(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRabbitmqTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceRabbitmqTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceRabbitmqTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
