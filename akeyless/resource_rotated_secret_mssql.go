package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRotatedSecretMsSql() *schema.Resource {
	return &schema.Resource{
		Description: "Mssql rotated secret resource",
		Create:      resourceRotatedSecretMsSqlCreate,
		Read:        resourceRotatedSecretMsSqlRead,
		Update:      resourceRotatedSecretMsSqlUpdate,
		Delete:      resourceRotatedSecretMsSqlDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRotatedSecretMsSqlImport,
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
			"rotator_type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The rotator type [target/password]",
			},
			"authentication_credentials": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The credentials to connect with use-user-creds/use-target-creds",
				Default:     "use-user-creds",
			},
			"rotated_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "username to be rotated, if selected use-self-creds at rotator-creds-type, this username will try to rotate it's own password, if use-target-creds is selected, target credentials will be use to rotate the rotated-password (relevant only for rotator-type=password)",
			},
			"rotated_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "rotated-username password (relevant only for rotator-type=password)",
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

func resourceRotatedSecretMsSqlCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
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
	rotatedUsername := d.Get("rotated_username").(string)
	rotatedPassword := d.Get("rotated_password").(string)

	body := akeyless.RotatedSecretCreateMssql{
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
	common.GetAkeylessPtr(&body.RotatedUsername, rotatedUsername)
	common.GetAkeylessPtr(&body.RotatedPassword, rotatedPassword)

	_, _, err := client.RotatedSecretCreateMssql(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create rotated secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create rotated secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretMsSqlRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.RotatedSecretGetValue{
		Name:  path,
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
		err = common.SetDataByPrefixSlash(d, "target_name", targetName, d.Get("target_name").(string))
		if err != nil {
			return err
		}
	}
	if itemOut.ItemMetadata != nil {
		err := common.SetDescriptionBc(d, *itemOut.ItemMetadata)
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

	rOut, res, err := client.RotatedSecretGetValue(ctx).Body(body).Execute()
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
	_ = rotatorType
	_ = value
	if ok {
		// val, ok := value.(map[string]interface{})
		// if ok {
		// 	switch rotatorType {
		// 	case "user-pass-rotator":
		// 		err = d.Set("rotated_username", fmt.Sprintf("%v", val["username"]))
		// 		if err != nil {
		// 			return err
		// 		}
		// 		err = d.Set("rotated_password", fmt.Sprintf("%v", val["password"]))
		// 		if err != nil {
		// 			return err
		// 		}
		// 	case "api-key-rotator":
		// 		err = d.Set("api_id", fmt.Sprintf("%v", val["username"]))
		// 		if err != nil {
		// 			return err
		// 		}
		// 		err = d.Set("api_key", fmt.Sprintf("%v", val["password"]))
		// 		if err != nil {
		// 			return err
		// 		}
		// 	case "custom-rotator":
		// 		err = d.Set("custom_payload", fmt.Sprintf("%v", val["payload"]))
		// 		if err != nil {
		// 			return err
		// 		}
		// 	case "ldap-rotator":
		// 		ldapPayloadInBytes, err := json.Marshal(val["ldap_payload"])
		// 		if err != nil {
		// 			return err
		// 		}
		// 		var ldapPayload map[string]interface{}
		// 		err = json.Unmarshal(ldapPayloadInBytes, &ldapPayload)
		// 		if err != nil {
		// 			return err
		// 		}
		// 		err = d.Set("user_attribute", fmt.Sprintf("%v", ldapPayload["ldap_user_attr"]))
		// 		if err != nil {
		// 			return err
		// 		}
		// 		err = d.Set("user_dn", fmt.Sprintf("%v", ldapPayload["ldap_user_dn"]))
		// 		if err != nil {
		// 			return err
		// 		}
		// 	case "azure-storage-account-rotator":
		// 	case "service-account-rotator":
		// 	default:
		// 	}
		// }
	}

	d.SetId(path)

	return nil
}

func resourceRotatedSecretMsSqlUpdate(d *schema.ResourceData, m interface{}) error {

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	autoRotate := d.Get("auto_rotate").(string)
	rotationInterval := d.Get("rotation_interval").(string)
	rotationHour := d.Get("rotation_hour").(int)
	authenticationCredentials := d.Get("authentication_credentials").(string)
	rotatedUsername := d.Get("rotated_username").(string)
	rotatedPassword := d.Get("rotated_password").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless.RotatedSecretUpdateMssql{
		Name:    name,
		NewName: akeyless.PtrString(name),
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
	common.GetAkeylessPtr(&body.AuthenticationCredentials, authenticationCredentials)
	common.GetAkeylessPtr(&body.RotatedUsername, rotatedUsername)
	common.GetAkeylessPtr(&body.RotatedPassword, rotatedPassword)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err = client.RotatedSecretUpdateMssql(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update rotated secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update rotated secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretMsSqlDelete(d *schema.ResourceData, m interface{}) error {
	return resourceRotatedSecretCommonDelete(d, m)
}

func resourceRotatedSecretMsSqlImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	return resourceRotatedSecretCommonImport(d, m)
}
