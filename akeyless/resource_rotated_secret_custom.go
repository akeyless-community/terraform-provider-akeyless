package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRotatedSecretCustom() *schema.Resource {
	return &schema.Resource{
		Description: "Custom rotated secret resource",
		Create:      resourceRotatedSecretCustomCreate,
		Read:        resourceRotatedSecretCustomRead,
		Update:      resourceRotatedSecretCustomUpdate,
		Delete:      resourceRotatedSecretCustomDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRotatedSecretCustomImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Secret name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The target name to associate",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"custom_payload": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Secret payload to be sent with rotation request",
			},
			"auto_rotate": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to automatically rotate every --rotation-interval days, or disable existing automatic rotation",
			},
			"rotation_interval": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The number of days to wait between every automatic rotation (1-365),custom rotator interval will be set in minutes",
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
				Description: "The name of a key that is used to encrypt the secret value (if empty, the account default protectionKey key will be used)",
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

func resourceRotatedSecretCustomCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
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
	customPayload := d.Get("custom_payload").(string)

	body := akeyless_api.RotatedSecretCreateCustom{
		Name:       name,
		TargetName: targetName,
		Token:      &token,
	}
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.AutoRotate, autoRotate)
	common.GetAkeylessPtr(&body.RotationInterval, rotationInterval)
	common.GetAkeylessPtr(&body.RotationHour, rotationHour)
	common.GetAkeylessPtr(&body.CustomPayload, customPayload)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)

	_, _, err := client.RotatedSecretCreateCustom(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create rotated secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create rotated secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretCustomRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
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
		err = d.Set("tags", *itemOut.ItemTags)
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

	if itemOut.ItemGeneralInfo != nil && itemOut.ItemGeneralInfo.RotatedSecretDetails != nil {
		rsd := itemOut.ItemGeneralInfo.RotatedSecretDetails
		if rsd.RotationHour != nil {
			err = d.Set("rotation_hour", *rsd.RotationHour)
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

	value, ok := rOut["value"]
	if ok {
		if payload, ok := value["payload"]; ok {
			err := d.Set("custom_payload", payload.(string))
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceRotatedSecretCustomUpdate(d *schema.ResourceData, m interface{}) error {

	provider := m.(providerMeta)
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
	customPayload := d.Get("custom_payload").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless_api.RotatedSecretUpdateCustom{
		Name:    name,
		NewName: akeyless_api.PtrString(name),
		Token:   &token,
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
	common.GetAkeylessPtr(&body.CustomPayload, customPayload)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)

	_, _, err = client.RotatedSecretUpdateCustom(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update rotated secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update rotated secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretCustomDelete(d *schema.ResourceData, m interface{}) error {
	return resourceRotatedSecretCommonDelete(d, m)
}

func resourceRotatedSecretCustomImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceRotatedSecretCustomRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
