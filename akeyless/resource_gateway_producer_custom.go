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

func resourceProducerCustom() *schema.Resource {
	return &schema.Resource{
		Description:        "Custom producer resource",
		DeprecationMessage: "Deprecated: Please use new resource: akeyless_dynamic_secret_custom",
		Create:             resourceProducerCustomCreate,
		Read:               resourceProducerCustomRead,
		Update:             resourceProducerCustomUpdate,
		Delete:             resourceProducerCustomDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerCustomImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Producer name",
				ForceNew:    true,
			},
			"create_sync_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "URL of an endpoint that implements /sync/create method",
			},
			"revoke_sync_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "URL of an endpoint that implements /sync/revoke method",
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
			"rotate_sync_url": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "URL of an endpoint that implements /sync/rotate method",
			},
			"payload": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Secret payload to be sent with each create/revoke webhook request",
			},
			"timeout_sec": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Maximum allowed time in seconds for the webhook to return the results",
				Default:     "60",
			},
			"enable_admin_rotation": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable automatic admin credentials rotation",
				Default:     "false",
			},
			"admin_rotation_interval_days": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Rotation period in days",
			},
		},
	}
}

func resourceProducerCustomCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	createSyncUrl := d.Get("create_sync_url").(string)
	revokeSyncUrl := d.Get("revoke_sync_url").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	rotateSyncUrl := d.Get("rotate_sync_url").(string)
	payload := d.Get("payload").(string)
	timeoutSec := d.Get("timeout_sec").(int)
	enableAdminRotation := d.Get("enable_admin_rotation").(bool)
	adminRotationIntervalDays := d.Get("admin_rotation_interval_days").(int)

	body := akeyless.GatewayCreateProducerCustom{
		Name:          name,
		CreateSyncUrl: createSyncUrl,
		RevokeSyncUrl: revokeSyncUrl,
		Token:         &token,
	}
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.RotateSyncUrl, rotateSyncUrl)
	common.GetAkeylessPtr(&body.Payload, payload)
	common.GetAkeylessPtr(&body.TimeoutSec, timeoutSec)
	common.GetAkeylessPtr(&body.EnableAdminRotation, enableAdminRotation)
	common.GetAkeylessPtr(&body.AdminRotationIntervalDays, adminRotationIntervalDays)

	_, _, err := client.GatewayCreateProducerCustom(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerCustomRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.CreateSyncUrl != nil {
		err = d.Set("create_sync_url", *rOut.CreateSyncUrl)
		if err != nil {
			return err
		}
	}
	if rOut.RevokeSyncUrl != nil {
		err = d.Set("revoke_sync_url", *rOut.RevokeSyncUrl)
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
	if rOut.RotateSyncUrl != nil {
		err = d.Set("rotate_sync_url", *rOut.RotateSyncUrl)
		if err != nil {
			return err
		}
	}
	if rOut.Payload != nil {
		err = d.Set("payload", *rOut.Payload)
		if err != nil {
			return err
		}
	}
	if rOut.EnableAdminRotation != nil {
		err = d.Set("enable_admin_rotation", *rOut.EnableAdminRotation)
		if err != nil {
			return err
		}
	}
	if rOut.AdminRotationIntervalDays != nil {
		err = d.Set("admin_rotation_interval_days", *rOut.AdminRotationIntervalDays)
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
	if rOut.TimeoutSeconds != nil {
		err = d.Set("timeout_sec", *rOut.TimeoutSeconds)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceProducerCustomUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	createSyncUrl := d.Get("create_sync_url").(string)
	revokeSyncUrl := d.Get("revoke_sync_url").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	rotateSyncUrl := d.Get("rotate_sync_url").(string)
	payload := d.Get("payload").(string)
	timeoutSec := d.Get("timeout_sec").(int)
	enableAdminRotation := d.Get("enable_admin_rotation").(bool)
	adminRotationIntervalDays := d.Get("admin_rotation_interval_days").(int)

	body := akeyless.GatewayUpdateProducerCustom{
		Name:          name,
		CreateSyncUrl: createSyncUrl,
		RevokeSyncUrl: revokeSyncUrl,
		Token:         &token,
	}
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.RotateSyncUrl, rotateSyncUrl)
	common.GetAkeylessPtr(&body.Payload, payload)
	common.GetAkeylessPtr(&body.TimeoutSec, timeoutSec)
	common.GetAkeylessPtr(&body.EnableAdminRotation, enableAdminRotation)
	common.GetAkeylessPtr(&body.AdminRotationIntervalDays, adminRotationIntervalDays)

	_, _, err := client.GatewayUpdateProducerCustom(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerCustomDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceProducerCustomImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceProducerCustomRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
