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

func resourceRotatedSecret() *schema.Resource {
	return &schema.Resource{
		Description: "Rotated secret resource",
		Create:      resourceRotatedSecretCreate,
		Read:        resourceRotatedSecretRead,
		Update:      resourceRotatedSecretUpdate,
		Delete:      resourceRotatedSecretDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRotatedSecretImport,
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
			"metadata": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Metadata about the secret",
			},
			"tags": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The name of a key that is used to encrypt the secret value (if empty, the account default protectionKey key will be used)",
			},
			"auto_rotate": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Whether to automatically rotate every --rotation-interval days, or disable existing automatic rotation",
			},
			"rotation_interval": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "The number of days to wait between every automatic rotation (1-365),custom rotator interval will be set in minutes",
			},
			"rotation_hour": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "The Hour of the rotation in UTC",
			},
			"rotator_type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The rotator type password/target/api-key/ldap/custom",
			},
			"rotator_creds_type": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The credentials to connect with use-user-creds/use-target-creds ",
				Default:     "use-user-creds",
			},
			"rotator_custom_cmd": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Custom rotation command (relevant only for ssh target)",
			},
			"api_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "API ID to rotate (relevant only for rotator-type=api-key)",
			},
			"api_key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "API key to rotate (relevant only for rotator-type=api-key)",
			},
			"rotated_username": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "username to be rotated, if selected use-self-creds at rotator-creds-type, this username will try to rotate it's own password, if use-target-creds is selected, target credentials will be use to rotate the rotated-password (relevant only for rotator-type=password)",
			},
			"rotated_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "rotated-username password (relevant only for rotator-type=password)",
			},
			"user_dn": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Base DN to Perform User Search",
			},
			"user_attribute": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "LDAP User Attribute",
			},
			"custom_payload": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Secret payload to be sent with rotation request (relevant only for rotator-type=custom)",
			},
		},
	}
}

func resourceRotatedSecretCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	fmt.Println("-- create --")

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	metadata := d.Get("metadata").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	key := d.Get("key").(string)
	autoRotate := d.Get("auto_rotate").(bool)
	rotationInterval := d.Get("rotation_interval").(int)
	rotationHour := d.Get("rotation_hour").(int)
	rotatorType := d.Get("rotator_type").(string)
	rotatorCredsType := d.Get("rotator_creds_type").(string)
	rotatorCustomCmd := d.Get("rotator_custom_cmd").(string)
	apiId := d.Get("api_id").(string)
	apiKey := d.Get("api_key").(string)
	rotatedUsername := d.Get("rotated_username").(string)
	rotatedPassword := d.Get("rotated_password").(string)
	userDn := d.Get("user_dn").(string)
	userAttribute := d.Get("user_attribute").(string)
	customPayload := d.Get("custom_payload").(string)

	body := akeyless.CreateRotatedSecret{
		Name:        name,
		TargetName:  targetName,
		RotatorType: rotatorType,
		Token:       &token,
	}
	common.GetAkeylessPtr(&body.Metadata, metadata)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.AutoRotate, autoRotate)
	common.GetAkeylessPtr(&body.RotationInterval, rotationInterval)
	common.GetAkeylessPtr(&body.RotationHour, rotationHour)
	common.GetAkeylessPtr(&body.RotatorCredsType, rotatorCredsType)
	common.GetAkeylessPtr(&body.RotatorCustomCmd, rotatorCustomCmd)
	common.GetAkeylessPtr(&body.ApiId, apiId)
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.RotatedUsername, rotatedUsername)
	common.GetAkeylessPtr(&body.RotatedPassword, rotatedPassword)
	common.GetAkeylessPtr(&body.UserDn, userDn)
	common.GetAkeylessPtr(&body.UserAttribute, userAttribute)
	common.GetAkeylessPtr(&body.CustomPayload, customPayload)

	_, _, err := client.CreateRotatedSecret(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	fmt.Println("-- read --")

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GetRotatedSecretValue{
		Names: path,
		Token: &token,
	}

	item := akeyless.DescribeItem{
		Name:         path,
		ShowVersions: akeyless.PtrBool(true),
		Token:        &token,
	}

	itemOut, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return err
	}

	if itemOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(itemOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
		if err != nil {
			return err
		}
	}
	if itemOut.ItemMetadata != nil {
		err = d.Set("metadata", *itemOut.ItemMetadata)
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
		err = d.Set("auto_rotate", *itemOut.AutoRotate)
		if err != nil {
			return err
		}
	}
	if itemOut.RotationInterval != nil {
		err = d.Set("rotation_interval", *itemOut.RotationInterval)
		if err != nil {
			return err
		}
	}
	rType := "password"
	if itemOut.ItemGeneralInfo != nil && itemOut.ItemGeneralInfo.RotatedSecretDetails != nil {
		rsd := itemOut.ItemGeneralInfo.RotatedSecretDetails
		if rsd.RotationHour != nil {
			err = d.Set("rotation_hour", *rsd.RotationHour)
			if err != nil {
				return err
			}
		}
		if rsd.RotatorType != nil {
			if *rsd.RotatorType == "use_???" {
				err = d.Set("rotator_type", rType)
				if err != nil {
					return err
				}
			}
		}
		if rsd.RotatorCredsType != nil {
			err = d.Set("rotator_creds_type", *rsd.RotatorCredsType)
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

	rOut, res, err := client.GetRotatedSecretValue(ctx).Body(body).Execute()
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

	val, ok := rOut["value"]
	if ok {
		if _, ok := val["payload"]; ok {
			err = d.Set("custom_payload", fmt.Sprintf("%v", val["payload"]))
			if err != nil {
				return err
			}
		} else if _, ok := val["target_value"]; ok {

		} else if _, ok := val["username"]; ok {
			err = d.Set("rotated_username", fmt.Sprintf("%v", val["username"]))
			if err != nil {
				return err
			}
		} else if _, ok := val["password"]; ok {
			err = d.Set("custom_payload", fmt.Sprintf("%v", val["password"]))
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceRotatedSecretUpdate(d *schema.ResourceData, m interface{}) error {

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	fmt.Println("-- update --")

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	key := d.Get("key").(string)
	autoRotate := d.Get("auto_rotate").(bool)
	rotationInterval := d.Get("rotation_interval").(int)
	rotationHour := d.Get("rotation_hour").(int)
	rotatorCredsType := d.Get("rotator_creds_type").(string)
	apiId := d.Get("api_id").(string)
	apiKey := d.Get("api_key").(string)
	rotatedUsername := d.Get("rotated_username").(string)
	rotatedPassword := d.Get("rotated_password").(string)
	customPayload := d.Get("custom_payload").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	// targetName := d.Get("target_name").(string)
	// rotatorType := d.Get("rotator_type").(string)
	// userDn := d.Get("user_dn").(string)
	// userAttribute := d.Get("user_attribute").(string)
	// username := d.Get("username").(string)
	// password := d.Get("password").(string)
	metadata := d.Get("metadata").(string)
	rotatorCustomCmd := d.Get("rotator_custom_cmd").(string)

	body := akeyless.UpdateRotatedSecret{
		Name:  name,
		Token: &token,
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
	common.GetAkeylessPtr(&body.RotatorCredsType, rotatorCredsType)
	common.GetAkeylessPtr(&body.ApiId, apiId)
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.RotatedUsername, rotatedUsername)
	common.GetAkeylessPtr(&body.RotatedPassword, rotatedPassword)
	common.GetAkeylessPtr(&body.CustomPayload, customPayload)
	common.GetAkeylessPtr(&body.RotatorCustomCmd, rotatorCustomCmd)
	common.GetAkeylessPtr(&body.NewMetadata, metadata)

	// common.GetAkeylessPtr(&body.Username, username)
	// common.GetAkeylessPtr(&body.Password, password)

	_, _, err = client.UpdateRotatedSecret(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteItem{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	fmt.Println("--- delete: rotated secret ---")
	_, _, err := client.DeleteItem(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	fmt.Println("--- success delete rotated secret ---")

	return nil
}

func resourceRotatedSecretImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GetRotatedSecretValue{
		Names: path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GetRotatedSecretValue(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
