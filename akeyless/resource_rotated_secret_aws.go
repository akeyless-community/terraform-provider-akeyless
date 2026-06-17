package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRotatedSecretAws() *schema.Resource {
	return &schema.Resource{
		Description: "Aws rotated secret resource",
		Create:      resourceRotatedSecretAwsCreate,
		Read:        resourceRotatedSecretAwsRead,
		Update:      resourceRotatedSecretAwsUpdate,
		Delete:      resourceRotatedSecretAwsDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRotatedSecretAwsImport,
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
				Description: "The rotator type. options: [target/api-key]",
			},
			"authentication_credentials": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The credentials to connect with use-self-creds/use-target-creds",
				Default:     "use-self-creds",
			},
			"api_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "API ID to rotate (relevant only for rotator-type=api-key)",
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "API key to rotate (relevant only for rotator-type=api-key)",
			},
			"grace_rotation": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Create a new access key without deleting the old key from AWS/Azure/GCP for backup (relevant only for AWS/Azure/GCP) [true/false]",
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
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"aws_region": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Aws Region",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
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
				Computed:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"rotate_after_disconnect": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Rotate the value of the secret after SRA session ends [true/false]",
			},
			"rotation_event_in": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "How many days before the rotation of the item would you like to be notified",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_aws_account_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The AWS account id",
			},
			"secure_access_aws_native_cli": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "The AWS native cli",
			},
			"secure_access_certificate_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Secure Access",
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access [true/false]",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceRotatedSecretAwsCreate(d *schema.ResourceData, m interface{}) error {
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
	apiId := d.Get("api_id").(string)
	apiKey := d.Get("api_key").(string)
	graceRotation := d.Get("grace_rotation").(string)
	awsRegion := d.Get("aws_region").(string)
	deleteProtection := d.Get("delete_protection").(string)
	graceRotationHour := d.Get("grace_rotation_hour").(int)
	graceRotationInterval := d.Get("grace_rotation_interval").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	maxVersions := d.Get("max_versions").(string)
	rotateAfterDisconnect := d.Get("rotate_after_disconnect").(string)
	rotationEventInSet := d.Get("rotation_event_in").(*schema.Set)
	rotationEventIn := common.ExpandStringList(rotationEventInSet.List())
	secureAccessAwsAccountId := d.Get("secure_access_aws_account_id").(string)
	secureAccessAwsNativeCli := d.Get("secure_access_aws_native_cli").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)

	body := akeyless_api.RotatedSecretCreateAws{
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
	common.GetAkeylessPtr(&body.ApiId, apiId)
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.GraceRotation, graceRotation)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.AwsRegion, awsRegion)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.GraceRotationHour, graceRotationHour)
	common.GetAkeylessPtr(&body.GraceRotationInterval, graceRotationInterval)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.RotateAfterDisconnect, rotateAfterDisconnect)
	common.GetAkeylessPtr(&body.RotationEventIn, rotationEventIn)
	common.GetAkeylessPtr(&body.SecureAccessAwsAccountId, secureAccessAwsAccountId)
	common.GetAkeylessPtr(&body.SecureAccessAwsNativeCli, secureAccessAwsNativeCli)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.RotatedSecretCreateAws(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretAwsRead(d *schema.ResourceData, m interface{}) error {
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
		err := common.SetDataByPrefixSlash(d, "target_name", targetName, d.Get("target_name").(string))
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
		err := d.Set("tags", itemOut.ItemTags)
		if err != nil {
			return err
		}
	}
	if itemOut.ProtectionKeyName != nil {
		err := d.Set("key", *itemOut.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	if itemOut.AutoRotate != nil {
		if *itemOut.AutoRotate || d.Get("auto_rotate").(string) != "" {
			err := d.Set("auto_rotate", strconv.FormatBool(*itemOut.AutoRotate))
			if err != nil {
				return err
			}
		}
	}
	if itemOut.RotationInterval != nil {
		if *itemOut.RotationInterval != 0 || d.Get("rotation_interval").(string) != "" {
			err := d.Set("rotation_interval", strconv.Itoa(int(*itemOut.RotationInterval)))
			if err != nil {
				return err
			}
		}
	}

	var rotatorType = ""

	if itemOut.ItemGeneralInfo != nil && itemOut.ItemGeneralInfo.RotatedSecretDetails != nil {
		rsd := itemOut.ItemGeneralInfo.RotatedSecretDetails
		if rsd.RotationHour != nil {
			err := d.Set("rotation_hour", *rsd.RotationHour)
			if err != nil {
				return err
			}
		}

		if rsd.RotatorType != nil {
			rotatorType = *rsd.RotatorType
			err := setRotatorType(d, *rsd.RotatorType)
			if err != nil {
				return err
			}
		}

		if rsd.RotatorCredsType != nil {
			err := d.Set("authentication_credentials", *rsd.RotatorCredsType)
			if err != nil {
				return err
			}
		}
		if rsd.GraceRotation != nil {
			if *rsd.GraceRotation || d.Get("grace_rotation").(string) != "" {
				err := d.Set("grace_rotation", strconv.FormatBool(*rsd.GraceRotation))
				if err != nil {
					return err
				}
			}
		}
		if rsd.GraceRotationHour != nil {
			err := d.Set("grace_rotation_hour", *rsd.GraceRotationHour)
			if err != nil {
				return err
			}
		}
		if rsd.GraceRotationInterval != nil {
			if *rsd.GraceRotationInterval != 0 || d.Get("grace_rotation_interval").(string) != "" {
				err := d.Set("grace_rotation_interval", strconv.Itoa(int(*rsd.GraceRotationInterval)))
				if err != nil {
					return err
				}
			}
		}
		if rsd.MaxVersions != nil {
			err := d.Set("max_versions", strconv.Itoa(int(*rsd.MaxVersions)))
			if err != nil {
				return err
			}
		}
	}

	if itemOut.ItemGeneralInfo != nil && itemOut.ItemGeneralInfo.SecureRemoteAccessDetails != nil {
		sra := itemOut.ItemGeneralInfo.SecureRemoteAccessDetails
		if sra.RotateAfterDisconnect != nil {
			if *sra.RotateAfterDisconnect || d.Get("rotate_after_disconnect").(string) != "" {
				err := d.Set("rotate_after_disconnect", strconv.FormatBool(*sra.RotateAfterDisconnect))
				if err != nil {
					return err
				}
			}
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
	if itemOut.ItemCustomFieldsDetails != nil {
		customFields := make(map[string]string)
		for _, field := range itemOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		if len(customFields) > 0 {
			err := d.Set("item_custom_fields", customFields)
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
			case common.ApiKeyRotator:
				if username, ok := value["username"]; ok {
					err := d.Set("api_id", username.(string))
					if err != nil {
						return err
					}
				}
				if password, ok := value["password"]; ok {
					err := d.Set("api_key", password.(string))
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

func resourceRotatedSecretAwsUpdate(d *schema.ResourceData, m interface{}) error {

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
	apiId := d.Get("api_id").(string)
	apiKey := d.Get("api_key").(string)
	graceRotation := d.Get("grace_rotation").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	awsRegion := d.Get("aws_region").(string)
	deleteProtection := d.Get("delete_protection").(string)
	graceRotationHour := d.Get("grace_rotation_hour").(int)
	graceRotationInterval := d.Get("grace_rotation_interval").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	maxVersions := d.Get("max_versions").(string)
	rotateAfterDisconnect := d.Get("rotate_after_disconnect").(string)
	rotationEventInSet := d.Get("rotation_event_in").(*schema.Set)
	rotationEventIn := common.ExpandStringList(rotationEventInSet.List())
	secureAccessAwsAccountId := d.Get("secure_access_aws_account_id").(string)
	secureAccessAwsNativeCli := d.Get("secure_access_aws_native_cli").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.RotatedSecretUpdateAws{
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
	common.GetAkeylessPtr(&body.ApiId, apiId)
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.GraceRotation, graceRotation)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.AwsRegion, awsRegion)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.GraceRotationHour, graceRotationHour)
	common.GetAkeylessPtr(&body.GraceRotationInterval, graceRotationInterval)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.RotateAfterDisconnect, rotateAfterDisconnect)
	common.GetAkeylessPtr(&body.RotationEventIn, rotationEventIn)
	common.GetAkeylessPtr(&body.SecureAccessAwsAccountId, secureAccessAwsAccountId)
	common.GetAkeylessPtr(&body.SecureAccessAwsNativeCli, secureAccessAwsNativeCli)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.RotatedSecretUpdateAws(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretAwsDelete(d *schema.ResourceData, m interface{}) error {
	return resourceRotatedSecretCommonDelete(d, m)
}

func resourceRotatedSecretAwsImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceRotatedSecretAwsRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
