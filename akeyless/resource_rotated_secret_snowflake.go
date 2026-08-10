package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceRotatedSecretSnowflake() *schema.Resource {
	return &schema.Resource{
		Description: "Snowflake rotated secret resource",
		Create:      resourceRotatedSecretSnowflakeCreate,
		Read:        resourceRotatedSecretSnowflakeRead,
		Update:      resourceRotatedSecretSnowflakeUpdate,
		Delete:      resourceRotatedSecretSnowflakeDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRotatedSecretSnowflakeImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("rotated_password"), cty.GetAttrPath("rotated_password_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("private_key"), cty.GetAttrPath("private_key_wo")),
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
				Description: "The rotator type. options: [target/password/key]",
			},
			"authentication_credentials": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The credentials to connect with use-self-creds/use-target-creds",
				Default:     "use-self-creds",
			},
			"rotated_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "username to be rotated, if selected use-self-creds at rotator-creds-type, this username will try to rotate it's own password, if use-target-creds is selected, target credentials will be use to rotate the rotated-password (relevant only for rotator-type=password or rotator-type=key)",
			},
			"rotated_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "rotated-username password (relevant only for rotator-type=password)",
			},
			"rotated_password_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"rotated_password_wo_version"},
				WriteOnly:    true,
				Description:  "rotated_password (write-only, not stored in state). Requires Terraform 1.11+. Bump rotated_password_wo_version to change it.",
			},
			"rotated_password_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"rotated_password_wo"},
				Description:  "Version trigger for rotated_password_wo. Increment to update the value.",
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
			"input_rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Password input rule definitions",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"output_rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Password output rule definitions",
				Elem:        &schema.Schema{Type: schema.TypeString},
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
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
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
				Computed:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"private_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "RSA Private key (base64 encoded) to rotate (relevant only for rotator-type=key)",
			},
			"private_key_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"private_key_wo_version"},
				WriteOnly:    true,
				Description:  "RSA Private key (base64 encoded) to rotate (write-only, not stored in state). Requires Terraform 1.11+. Bump private_key_wo_version to change it.",
			},
			"private_key_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"private_key_wo"},
				Description:  "Version trigger for private_key_wo. Increment to update the value.",
			},
			"private_key_file_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The path to the file containing the private key (relevant only for rotator-type=key)",
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

func resourceRotatedSecretSnowflakeCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	key := d.Get("key").(string)
	autoRotate := d.Get("auto_rotate").(string)
	rotationInterval := d.Get("rotation_interval").(string)
	rotationHour := d.Get("rotation_hour").(int)
	rotatorType := d.Get("rotator_type").(string)
	authenticationCredentials := d.Get("authentication_credentials").(string)
	rotatedUsername := d.Get("rotated_username").(string)
	rotatedPassword, err := common.EffectiveSecretValue(d, "rotated_password", "rotated_password_wo")
	if err != nil {
		return err
	}
	deleteProtection := d.Get("delete_protection").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	maxVersions := d.Get("max_versions").(string)
	privateKey, err := common.EffectiveSecretValue(d, "private_key", "private_key_wo")
	if err != nil {
		return err
	}
	privateKeyFileName := d.Get("private_key_file_name").(string)
	rotationEventInList := d.Get("rotation_event_in").([]interface{})
	rotationEventIn := common.ExpandStringList(rotationEventInList)

	body := akeyless_api.RotatedSecretCreateSnowflake{
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
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.ItemCustomFields, itemCustomFields)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.PrivateKey, privateKey)
	common.GetAkeylessPtr(&body.PrivateKeyFileName, privateKeyFileName)
	common.GetAkeylessPtr(&body.RotationEventIn, rotationEventIn)

	_, resp, err := client.RotatedSecretCreateSnowflake(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretSnowflakeRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

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
	deleteProtectionVal := "false"
	if itemOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*itemOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}
	if len(itemOut.ItemCustomFieldsDetails) > 0 {
		customFields := make(map[string]string)
		for _, field := range itemOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		err = d.Set("item_custom_fields", customFields)
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
		if rsd.MaxVersions != nil {
			err = d.Set("max_versions", strconv.Itoa(int(*rsd.MaxVersions)))
			if err != nil {
				return err
			}
		}
	}

	rOut, res, err := client.RotatedSecretGetValue(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get rotated secret value", res, err)
	}

	val, ok := rOut["value"]
	if ok {
		value, ok := val.(map[string]any)
		if ok {
			switch rotatorType {
			case common.UserPassRotator:
				if username, ok := value["username"]; ok {
					err := d.Set("rotated_username", username.(string))
					if err != nil {
						return err
					}
				}
				if password, ok := value["password"]; ok {
					err := common.SetSecretFromRead(d, "rotated_password", "rotated_password_wo", "rotated_password_wo_version", password.(string))
					if err != nil {
						return err
					}
				}
			}
		}
	}

	if err = setAgenticRulesReadFields(d, itemOut.ItemGeneralInfo.AgenticRules); err != nil {
		return err
	}
	if err = setRotatedSecretPasswordPolicyReadFields(d, itemOut.ItemGeneralInfo); err != nil {
		return err
	}

	d.SetId(path)

	return nil
}

func resourceRotatedSecretSnowflakeUpdate(d *schema.ResourceData, m interface{}) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	key := d.Get("key").(string)
	autoRotate := d.Get("auto_rotate").(string)
	rotationInterval := d.Get("rotation_interval").(string)
	rotationHour := d.Get("rotation_hour").(int)
	authenticationCredentials := d.Get("authentication_credentials").(string)
	rotatedUsername := d.Get("rotated_username").(string)
	rotatedPassword, err := common.SecretValueForUpdate(d, "rotated_password", "rotated_password_wo")
	if err != nil {
		return err
	}
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	maxVersions := d.Get("max_versions").(string)
	privateKey, err := common.SecretValueForUpdate(d, "private_key", "private_key_wo")
	if err != nil {
		return err
	}
	privateKeyFileName := d.Get("private_key_file_name").(string)
	rotationEventInList := d.Get("rotation_event_in").([]interface{})
	rotationEventIn := common.ExpandStringList(rotationEventInList)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.RotatedSecretUpdateSnowflake{
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
	common.GetAkeylessPtr(&body.AuthenticationCredentials, authenticationCredentials)
	common.GetAkeylessPtr(&body.RotatedUsername, rotatedUsername)
	common.SetOptionalString(&body.RotatedPassword, rotatedPassword)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.ItemCustomFields, itemCustomFields)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.SetOptionalString(&body.PrivateKey, privateKey)
	common.GetAkeylessPtr(&body.PrivateKeyFileName, privateKeyFileName)
	common.GetAkeylessPtr(&body.RotationEventIn, rotationEventIn)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.RotatedSecretUpdateSnowflake(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretSnowflakeDelete(d *schema.ResourceData, m interface{}) error {
	return resourceRotatedSecretCommonDelete(d, m)
}

func resourceRotatedSecretSnowflakeImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceRotatedSecretSnowflakeRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
