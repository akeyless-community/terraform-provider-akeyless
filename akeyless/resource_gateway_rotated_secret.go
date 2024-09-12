package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRotatedSecret() *schema.Resource {
	return &schema.Resource{
		Description:        "Rotated secret resource",
		DeprecationMessage: "Deprecated: Please use new resource: akeyless_rotated_secret_<TYPE>",
		Create:             resourceRotatedSecretCreate,
		Read:               resourceRotatedSecretRead,
		Update:             resourceRotatedSecretUpdate,
		Delete:             resourceRotatedSecretDelete,
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
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
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
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Whether to automatically rotate every --rotation-interval days, or disable existing automatic rotation",
			},
			"rotation_interval": {
				Type:        schema.TypeString,
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
			"authentication_credentials": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The credentials to connect with use-user-creds/use-target-creds",
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
				Computed:    true,
				Description: "API ID to rotate (relevant only for rotator-type=api-key)",
			},
			"api_key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "API key to rotate (relevant only for rotator-type=api-key)",
			},
			"rotated_username": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "username to be rotated, if selected use-self-creds at rotator-creds-type, this username will try to rotate it's own password, if use-target-creds is selected, target credentials will be use to rotate the rotated-password (relevant only for rotator-type=password)",
			},
			"rotated_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "rotated-username password (relevant only for rotator-type=password)",
			},
			"user_dn": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "Base DN to Perform User Search",
			},
			"user_attribute": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "LDAP User Attribute",
			},
			"custom_payload": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "Secret payload to be sent with rotation request (relevant only for rotator-type=custom)",
			},
		},
	}
}

func resourceRotatedSecretCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client

	ctx := context.Background()
	token, err := provider.getToken(ctx, d)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	var apiErr akeyless_api.GenericOpenAPIError

	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	key := d.Get("key").(string)
	autoRotate := d.Get("auto_rotate").(string)
	rotationInterval := d.Get("rotation_interval").(string)
	rotationHour := d.Get("rotation_hour").(int)
	rotatorType := d.Get("rotator_type").(string)
	authenticationCredentials := d.Get("authentication_credentials").(string)
	rotatorCustomCmd := d.Get("rotator_custom_cmd").(string)
	apiId := d.Get("api_id").(string)
	apiKey := d.Get("api_key").(string)
	rotatedUsername := d.Get("rotated_username").(string)
	rotatedPassword := d.Get("rotated_password").(string)
	userDn := d.Get("user_dn").(string)
	userAttribute := d.Get("user_attribute").(string)
	customPayload := d.Get("custom_payload").(string)

	body := akeyless_api.CreateRotatedSecret{
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
	common.GetAkeylessPtr(&body.RotatorCredsType, authenticationCredentials)
	common.GetAkeylessPtr(&body.RotatorCustomCmd, rotatorCustomCmd)
	common.GetAkeylessPtr(&body.ApiId, apiId)
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.RotatedUsername, rotatedUsername)
	common.GetAkeylessPtr(&body.RotatedPassword, rotatedPassword)
	common.GetAkeylessPtr(&body.UserDn, userDn)
	common.GetAkeylessPtr(&body.UserAttribute, userAttribute)
	common.GetAkeylessPtr(&body.CustomPayload, customPayload)

	_, _, err = client.CreateRotatedSecret(ctx).Body(body).Execute()
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
	provider := m.(*providerMeta)
	client := *provider.client

	ctx := context.Background()
	token, err := provider.getToken(ctx, d)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	var apiErr akeyless_api.GenericOpenAPIError

	path := d.Id()

	body := akeyless_api.GetRotatedSecretValue{
		Names: path,
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

	rOut, res, err := client.GetRotatedSecretValue(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}

			var out getDynamicSecretOutput
			err = json.Unmarshal(apiErr.Body(), &out)
			if err != nil {
				return fmt.Errorf("can't get value: %v", string(apiErr.Body()))
			}
		}
		if err != nil {
			return fmt.Errorf("can't get value: %v", err)
		}
	}

	value, ok := rOut["value"]
	if ok {
		var val map[string]interface{}
		val, ok = value.(map[string]interface{})
		if ok {
			if rotatorType == "custom" {
				err = d.Set("custom_payload", fmt.Sprintf("%v", val["payload"]))
				if err != nil {
					return err
				}
			} else if rotatorType == "ldap" {
				ldapPayloadInBytes, err := json.Marshal(val["ldap_payload"])
				if err != nil {
					return err
				}
				var ldapPayload map[string]interface{}
				err = json.Unmarshal(ldapPayloadInBytes, &ldapPayload)
				if err != nil {
					return err
				}
				err = d.Set("user_attribute", fmt.Sprintf("%v", ldapPayload["ldap_user_attr"]))
				if err != nil {
					return err
				}
				err = d.Set("user_dn", fmt.Sprintf("%v", ldapPayload["ldap_user_dn"]))
				if err != nil {
					return err
				}
			} else if rotatorType == "password" {
				err = d.Set("rotated_username", fmt.Sprintf("%v", val["username"]))
				if err != nil {
					return err
				}
				err = d.Set("rotated_password", fmt.Sprintf("%v", val["password"]))
				if err != nil {
					return err
				}
			} else if rotatorType == "api-key" {
				err = d.Set("api_id", fmt.Sprintf("%v", val["username"]))
				if err != nil {
					return err
				}
				err = d.Set("api_key", fmt.Sprintf("%v", val["password"]))
				if err != nil {
					return err
				}
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceRotatedSecretUpdate(d *schema.ResourceData, m interface{}) error {

	provider := m.(*providerMeta)
	client := *provider.client

	ctx := context.Background()
	token, err := provider.getToken(ctx, d)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	var apiErr akeyless_api.GenericOpenAPIError

	name := d.Get("name").(string)
	key := d.Get("key").(string)
	autoRotate := d.Get("auto_rotate").(string)
	rotationInterval := d.Get("rotation_interval").(string)
	rotationHour := d.Get("rotation_hour").(int)
	authenticationCredentials := d.Get("authentication_credentials").(string)
	apiId := d.Get("api_id").(string)
	apiKey := d.Get("api_key").(string)
	rotatedUsername := d.Get("rotated_username").(string)
	rotatedPassword := d.Get("rotated_password").(string)
	customPayload := d.Get("custom_payload").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	description := d.Get("description").(string)
	rotatorCustomCmd := d.Get("rotator_custom_cmd").(string)

	body := akeyless_api.UpdateRotatedSecret{
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
	common.GetAkeylessPtr(&body.RotatorCredsType, authenticationCredentials)
	common.GetAkeylessPtr(&body.RotatorCustomCmd, rotatorCustomCmd)
	common.GetAkeylessPtr(&body.ApiId, apiId)
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.RotatedUsername, rotatedUsername)
	common.GetAkeylessPtr(&body.RotatedPassword, rotatedPassword)
	common.GetAkeylessPtr(&body.CustomPayload, customPayload)
	common.GetAkeylessPtr(&body.Description, description)

	bodyItem := akeyless_api.UpdateItem{
		Name:    name,
		NewName: akeyless_api.PtrString(name),
		Token:   &token,
	}

	_, _, err = client.UpdateItem(ctx).Body(bodyItem).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update item: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update item: %v", err)
	}

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
	provider := m.(*providerMeta)
	client := *provider.client

	ctx := context.Background()
	token, err := provider.getToken(ctx, d)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	path := d.Id()

	deleteItem := akeyless_api.DeleteItem{
		Token: &token,
		Name:  path,
	}

	_, _, err = client.DeleteItem(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceRotatedSecretImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceRotatedSecretRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func setRotatorType(d *schema.ResourceData, rsdType string) error {

	switch rsdType {
	case "user-pass-rotator":
		return d.Set("rotator_type", "password")
	case "api-key-rotator":
		return d.Set("rotator_type", "api-key")
	case "custom-rotator":
		return d.Set("rotator_type", "custom")
	case "ldap-rotator":
		return d.Set("rotator_type", "ldap")
	case "azure-storage-account-rotator":
		return d.Set("rotator_type", "azure-storage-account")
	case "service-account-rotator":
		return d.Set("rotator_type", "service-account-rotator")
	case "target-rotator":
		return d.Set("rotator_type", "target")
	default:
		return fmt.Errorf("invalid rotator type")
	}
}

type getDynamicSecretOutput struct {
	DynamicSecretValue map[string]map[string]interface{} `json:"raw,omitempty"`
}
