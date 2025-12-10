package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretCustom() *schema.Resource {
	return &schema.Resource{
		Description: "Custom dynamic secret resource",
		Create:      resourceDynamicSecretCustomCreate,
		Read:        resourceDynamicSecretCustomRead,
		Update:      resourceDynamicSecretCustomUpdate,
		Delete:      resourceDynamicSecretCustomDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretCustomImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
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
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"rotate_sync_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL of an endpoint that implements /sync/rotate method",
			},
			"payload": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Secret payload to be sent with each create/revoke webhook request",
			},
			"timeout_sec": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum allowed time in seconds for the webhook to return the results",
				Default:     "60",
			},
			"enable_admin_rotation": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable automatic admin credentials rotation",
				Default:     "false",
			},
			"admin_rotation_interval_days": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Rotation period in days",
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

func resourceDynamicSecretCustomCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	createSyncUrl := d.Get("create_sync_url").(string)
	revokeSyncUrl := d.Get("revoke_sync_url").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	rotateSyncUrl := d.Get("rotate_sync_url").(string)
	payload := d.Get("payload").(string)
	timeoutSec := d.Get("timeout_sec").(int)
	enableAdminRotation := d.Get("enable_admin_rotation").(bool)
	adminRotationIntervalDays := d.Get("admin_rotation_interval_days").(int)

	body := akeyless_api.DynamicSecretCreateCustom{
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

	_, _, err := client.DynamicSecretCreateCustom(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretCustomRead(d *schema.ResourceData, m interface{}) error {
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
		err = d.Set("tags", rOut.Tags)
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
		err = common.SetDataByPrefixSlash(d, "encryption_key_name", *rOut.DynamicSecretKey, d.Get("encryption_key_name").(string))
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

func resourceDynamicSecretCustomUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	createSyncUrl := d.Get("create_sync_url").(string)
	revokeSyncUrl := d.Get("revoke_sync_url").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	rotateSyncUrl := d.Get("rotate_sync_url").(string)
	payload := d.Get("payload").(string)
	timeoutSec := d.Get("timeout_sec").(int)
	enableAdminRotation := d.Get("enable_admin_rotation").(bool)
	adminRotationIntervalDays := d.Get("admin_rotation_interval_days").(int)

	body := akeyless_api.DynamicSecretUpdateCustom{
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

	_, _, err := client.DynamicSecretUpdateCustom(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretCustomDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretCustomImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretCustomRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
