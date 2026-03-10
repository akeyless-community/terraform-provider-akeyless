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

func resourceRotatedSecretGcp() *schema.Resource {
	return &schema.Resource{
		Description: "Gcp rotated secret resource",
		Create:      resourceRotatedSecretGcpCreate,
		Read:        resourceRotatedSecretGcpRead,
		Update:      resourceRotatedSecretGcpUpdate,
		Delete:      resourceRotatedSecretGcpDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRotatedSecretGcpImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Rotated secret name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"rotator_type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The rotator type. options: [target/service-account-rotator]",
			},
			"authentication_credentials": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The credentials to connect with use-self-creds/use-target-creds",
				Default:     "use-self-creds",
			},
			"gcp_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Base64-encoded service account private key text",
			},
			"gcp_service_account_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The email of the gcp service account to rotate",
			},
			"gcp_service_account_key_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The key id of the gcp service account to rotate",
			},
			"auto_rotate": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to automatically rotate every --rotation-interval days, or disable existing automatic rotation [true/false]",
			},
			"rotation_interval": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The number of days to wait between every automatic key rotation (1-365)",
			},
			"rotation_hour": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The Hour of the rotation in UTC",
			},
			"password_length": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The length of the password to be generated",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that is used to encrypt the secret value (if empty, the account default protectionKey key will be used)",
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
			"grace_rotation": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Create a new access key without deleting the old key from AWS/Azure/GCP for backup (relevant only for AWS/Azure/GCP) [true/false]",
			},
			"grace_rotation_hour": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The Hour of the grace rotation in UTC",
			},
			"grace_rotation_interval": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The number of days to wait before deleting the old key (must be bigger than rotation-interval)",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"rotation_event_in": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "How many days before the rotation of the item would you like to be notified",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceRotatedSecretGcpCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	passwordLength := d.Get("password_length").(string)
	key := d.Get("key").(string)
	autoRotate := d.Get("auto_rotate").(string)
	rotationInterval := d.Get("rotation_interval").(string)
	rotationHour := d.Get("rotation_hour").(int)
	rotatorType := d.Get("rotator_type").(string)
	authenticationCredentials := d.Get("authentication_credentials").(string)
	gcpKey := d.Get("gcp_key").(string)
	gcpServiceAccountEmail := d.Get("gcp_service_account_email").(string)
	gcpServiceAccountKeyId := d.Get("gcp_service_account_key_id").(string)
	deleteProtection := d.Get("delete_protection").(string)
	graceRotation := d.Get("grace_rotation").(string)
	graceRotationHour := d.Get("grace_rotation_hour").(int)
	graceRotationInterval := d.Get("grace_rotation_interval").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.RotatedSecretCreateGcp{
		Name:        name,
		TargetName:  targetName,
		RotatorType: rotatorType,
		Token:       &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.AutoRotate, autoRotate)
	common.GetAkeylessPtr(&body.RotationInterval, rotationInterval)
	common.GetAkeylessPtr(&body.RotationHour, rotationHour)
	common.GetAkeylessPtr(&body.AuthenticationCredentials, authenticationCredentials)
	common.GetAkeylessPtr(&body.GcpKey, gcpKey)
	common.GetAkeylessPtr(&body.GcpServiceAccountEmail, gcpServiceAccountEmail)
	common.GetAkeylessPtr(&body.GcpServiceAccountKeyId, gcpServiceAccountKeyId)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.GraceRotation, graceRotation)
	common.GetAkeylessPtr(&body.GraceRotationHour, graceRotationHour)
	common.GetAkeylessPtr(&body.GraceRotationInterval, graceRotationInterval)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	if v, ok := d.GetOk("item_custom_fields"); ok {
		itemCustomFields := v.(map[string]interface{})
		fields := make(map[string]string)
		for k, val := range itemCustomFields {
			fields[k] = val.(string)
		}
		body.ItemCustomFields = &fields
	}

	if v, ok := d.GetOk("rotation_event_in"); ok {
		rotationEventIn := common.ExpandStringList(v.([]interface{}))
		body.RotationEventIn = rotationEventIn
	}

	_, _, err := client.RotatedSecretCreateGcp(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create rotated secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create rotated secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretGcpRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.RotatedSecretGetValue{
		Name:  path,
		Token: &token,
	}

	item := akeyless_api.DescribeItem{
		Name:         path,
		ShowVersions: akeyless_api.PtrBool(true),
		Token:        &token,
	}

	itemOut, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return err
	}

	if itemOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(itemOut.ItemTargetsAssoc)
		err = common.SetDataByPrefixSlash(d, "target_name", targetName, d.Get("target_name").(string))
		if err != nil {
			return err
		}
	}
	if itemOut.ItemMetadata != nil {
		err := d.Set("description", *itemOut.ItemMetadata)
		if err != nil {
			return err
		}
	}
	if itemOut.ItemTags != nil {
		err = d.Set("tags", itemOut.ItemTags)
		if err != nil {
			return err
		}
	}
	if itemOut.ProtectionKeyName != nil {
		err = d.Set("key", *itemOut.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	if itemOut.AutoRotate != nil {
		if *itemOut.AutoRotate || d.Get("auto_rotate").(string) != "" {
			err = d.Set("auto_rotate", strconv.FormatBool(*itemOut.AutoRotate))
			if err != nil {
				return err
			}
		}
	}
	if itemOut.RotationInterval != nil {
		if *itemOut.RotationInterval != 0 || d.Get("rotation_interval").(string) != "" {
			err = d.Set("rotation_interval", strconv.Itoa(int(*itemOut.RotationInterval)))
			if err != nil {
				return err
			}
		}
	}

	var rotatorType = ""

	if itemOut.ItemGeneralInfo != nil && itemOut.ItemGeneralInfo.RotatedSecretDetails != nil {
		rsd := itemOut.ItemGeneralInfo.RotatedSecretDetails
		if rsd.RotationHour != nil {
			err = d.Set("rotation_hour", *rsd.RotationHour)
			if err != nil {
				return err
			}
		}

		if rsd.RotatorType != nil {
			rotatorType = *rsd.RotatorType
			err = setRotatorType(d, *rsd.RotatorType)
			if err != nil {
				return err
			}
		}

		if rsd.RotatorCredsType != nil {
			err = d.Set("authentication_credentials", *rsd.RotatorCredsType)
			if err != nil {
				return err
			}
		}
		if rsd.RotationStatement != nil {
			err = d.Set("rotator_custom_cmd", *rsd.RotationStatement)
			if err != nil {
				return err
			}
		}
	}

	rOut, res, err := client.RotatedSecretGetValue(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't get rotated secret value: %v", err)
		}
	}

	val, ok := rOut["value"]
	if ok {
		value, ok := val.(map[string]any)
		if ok {
			switch rotatorType {
			case common.ServiceAccountRotator:
				if saKey, ok := value["service_account_key_base64"]; ok {
					err := d.Set("gcp_key", saKey.(string))
					if err != nil {
						return err
					}
				}
				if saEmail, ok := value["service_account_email"]; ok {
					err := d.Set("gcp_service_account_email", saEmail.(string))
					if err != nil {
						return err
					}
				}
				if saKeyId, ok := value["service_account_key_id"]; ok {
					err := d.Set("gcp_service_account_key_id", saKeyId.(string))
					if err != nil {
						return err
					}
				}
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceRotatedSecretGcpUpdate(d *schema.ResourceData, m interface{}) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	passwordLength := d.Get("password_length").(string)
	key := d.Get("key").(string)
	autoRotate := d.Get("auto_rotate").(string)
	rotationInterval := d.Get("rotation_interval").(string)
	rotationHour := d.Get("rotation_hour").(int)
	authenticationCredentials := d.Get("authentication_credentials").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	gcpKey := d.Get("gcp_key").(string)
	gcpServiceAccountEmail := d.Get("gcp_service_account_email").(string)
	gcpServiceAccountKeyId := d.Get("gcp_service_account_key_id").(string)
	deleteProtection := d.Get("delete_protection").(string)
	graceRotation := d.Get("grace_rotation").(string)
	graceRotationHour := d.Get("grace_rotation_hour").(int)
	graceRotationInterval := d.Get("grace_rotation_interval").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)
	rotatorType := d.Get("rotator_type").(string)

	body := akeyless_api.RotatedSecretUpdateGcp{
		Name:        name,
		RotatorType: rotatorType,
		Token:       &token,
	}
	add, remove, err := common.GetTagsForUpdate(d, name, token, tags, client)
	if err == nil {
		if len(add) > 0 {
			common.GetAkeylessPtr(&body.AddTag, add)
		}
		if len(remove) > 0 {
			common.GetAkeylessPtr(&body.RmTag, remove)
		}
	}

	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.AutoRotate, autoRotate)
	common.GetAkeylessPtr(&body.RotationInterval, rotationInterval)
	common.GetAkeylessPtr(&body.RotationHour, rotationHour)
	common.GetAkeylessPtr(&body.AuthenticationCredentials, authenticationCredentials)
	common.GetAkeylessPtr(&body.GcpKey, gcpKey)
	common.GetAkeylessPtr(&body.GcpServiceAccountEmail, gcpServiceAccountEmail)
	common.GetAkeylessPtr(&body.GcpServiceAccountKeyId, gcpServiceAccountKeyId)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.GraceRotation, graceRotation)
	common.GetAkeylessPtr(&body.GraceRotationHour, graceRotationHour)
	common.GetAkeylessPtr(&body.GraceRotationInterval, graceRotationInterval)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	if v, ok := d.GetOk("item_custom_fields"); ok {
		itemCustomFields := v.(map[string]interface{})
		fields := make(map[string]string)
		for k, val := range itemCustomFields {
			fields[k] = val.(string)
		}
		body.ItemCustomFields = &fields
	}

	if v, ok := d.GetOk("rotation_event_in"); ok {
		rotationEventIn := common.ExpandStringList(v.([]interface{}))
		body.RotationEventIn = rotationEventIn
	}

	_, _, err = client.RotatedSecretUpdateGcp(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update rotated secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update rotated secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretGcpDelete(d *schema.ResourceData, m interface{}) error {
	return resourceRotatedSecretCommonDelete(d, m)
}

func resourceRotatedSecretGcpImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceRotatedSecretGcpRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
