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
				Description: "URL of an endpoint that implements /sync/create method, for example https://webhook.example.com/sync/create",
			},
			"revoke_sync_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "URL of an endpoint that implements /sync/revoke method, for example https://webhook.example.com/sync/revoke",
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
				Description: "URL of an endpoint that implements /sync/rotate method, for example https://webhook.example.com/sync/rotate",
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
				Description: "Should admin credentials be rotated",
				Default:     false,
			},
			"admin_rotation_interval_days": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Define rotation interval in days",
			},
			"encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Dynamic producer encryption key",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
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
		},
	}
}

func resourceDynamicSecretCustomCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

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
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

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
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		customFields := make(map[string]string)
		for k, v := range itemCustomFields {
			customFields[k] = v.(string)
		}
		body.ItemCustomFields = &customFields
	}

	_, resp, err := client.DynamicSecretCreateCustom(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
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
		err = d.Set("item_custom_fields", customFields)
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
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

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
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		customFields := make(map[string]string)
		for k, v := range itemCustomFields {
			customFields[k] = v.(string)
		}
		body.ItemCustomFields = &customFields
	}

	_, resp, err := client.DynamicSecretUpdateCustom(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
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
