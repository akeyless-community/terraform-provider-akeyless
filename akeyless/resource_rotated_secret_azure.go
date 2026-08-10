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

func resourceRotatedSecretAzure() *schema.Resource {
	return &schema.Resource{
		Description: "Azure rotated secret resource",
		Create:      resourceRotatedSecretAzureCreate,
		Read:        resourceRotatedSecretAzureRead,
		Update:      resourceRotatedSecretAzureUpdate,
		Delete:      resourceRotatedSecretAzureDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRotatedSecretAzureImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("api_key"), cty.GetAttrPath("api_key_wo")),
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
				Description: "The rotator type. options: [target/password/api-key/azure-storage-account]",
			},
			"authentication_credentials": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The credentials to connect with use-self-creds/use-target-creds",
				Default:     "use-self-creds",
			},
			"app_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Id of the azure app that hold the serect to be rotated (relevant only for rotator-type=api-key & authentication-credentials=use-target-creds)",
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
			"api_key_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"api_key_wo_version"},
				WriteOnly:    true,
				Description:  "api_key (write-only, not stored in state). Requires Terraform 1.11+. Bump api_key_wo_version to change it.",
			},
			"api_key_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"api_key_wo"},
				Description:  "Version trigger for api_key_wo. Increment to update the value.",
			},
			"storage_account_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of the storage account key to rotate [key1/key2/kerb1/kerb2] (relevat to azure-storage-account)",
			},
			"username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The user principal name to rotate his password (relevant only for rotator-type=password)",
			},
			"auto_rotate": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to automatically rotate every --rotation-interval days, or disable existing automatic rotation",
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
			"explicitly_set_sa": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "If set, explicitly provide the storage account details [true/false]",
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
				Computed:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"resource_group_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The resource group name (only relevant when explicitly-set-sa=true)",
			},
			"resource_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of the storage account (only relevant when explicitly-set-sa=true)",
			},
			"rotate_after_disconnect": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Rotate the value of the secret after SRA session ends [true/false]",
			},
			"rotation_event_in": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "How many days before the rotation of the item would you like to be notified",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_disable_concurrent_connections": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable this flag to prevent simultaneous use of the same secret",
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access [true/false]",
			},
			"secure_access_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Destination URL to inject secrets",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable Web Secure Remote Access",
			},
			"secure_access_web_browsing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Secure browser via Akeyless's Secure Remote Access (SRA)",
			},
			"secure_access_web_proxy": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Web-Proxy via Akeyless's Secure Remote Access (SRA)",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceRotatedSecretAzureCreate(d *schema.ResourceData, m interface{}) error {
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
	appId := d.Get("app_id").(string)
	apiId := d.Get("api_id").(string)
	apiKey, err := common.EffectiveSecretValue(d, "api_key", "api_key_wo")
	if err != nil {
		return err
	}
	storageAccountKeyName := d.Get("storage_account_key_name").(string)
	username := d.Get("username").(string)
	deleteProtection := d.Get("delete_protection").(string)
	explicitlySetSa := d.Get("explicitly_set_sa").(string)
	graceRotation := d.Get("grace_rotation").(string)
	graceRotationHour := d.Get("grace_rotation_hour").(int)
	graceRotationInterval := d.Get("grace_rotation_interval").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	maxVersions := d.Get("max_versions").(string)
	resourceGroupName := d.Get("resource_group_name").(string)
	resourceName := d.Get("resource_name").(string)
	rotateAfterDisconnect := d.Get("rotate_after_disconnect").(string)
	rotationEventInList := d.Get("rotation_event_in").([]interface{})
	rotationEventIn := common.ExpandStringList(rotationEventInList)
	secureAccessDisableConcurrentConnections := d.Get("secure_access_disable_concurrent_connections").(bool)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessUrl := d.Get("secure_access_url").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)

	body := akeyless_api.RotatedSecretCreateAzure{
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
	common.GetAkeylessPtr(&body.ApplicationId, appId)
	common.GetAkeylessPtr(&body.ApiId, apiId)
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.StorageAccountKeyName, storageAccountKeyName)
	common.GetAkeylessPtr(&body.Username, username)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.ExplicitlySetSa, explicitlySetSa)
	common.GetAkeylessPtr(&body.GraceRotation, graceRotation)
	common.GetAkeylessPtr(&body.GraceRotationHour, graceRotationHour)
	common.GetAkeylessPtr(&body.GraceRotationInterval, graceRotationInterval)
	if len(itemCustomFields) > 0 {
		customFieldsMap := make(map[string]string)
		for k, v := range itemCustomFields {
			customFieldsMap[k] = v.(string)
		}
		body.ItemCustomFields = &customFieldsMap
	}
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.ResourceGroupName, resourceGroupName)
	common.GetAkeylessPtr(&body.ResourceName, resourceName)
	common.GetAkeylessPtr(&body.RotateAfterDisconnect, rotateAfterDisconnect)
	common.GetAkeylessPtr(&body.RotationEventIn, rotationEventIn)
	common.GetAkeylessPtr(&body.SecureAccessDisableConcurrentConnections, secureAccessDisableConcurrentConnections)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)

	_, resp, err := client.RotatedSecretCreateAzure(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretAzureRead(d *schema.ResourceData, m interface{}) error {
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
			case common.UserPassRotator:
				if username, ok := value["username"]; ok {
					err := d.Set("username", username.(string))
					if err != nil {
						return err
					}
				}
			case common.ApiKeyRotator:
				if username, ok := value["username"]; ok {
					err := d.Set("api_id", username.(string))
					if err != nil {
						return err
					}
				}
				if password, ok := value["password"]; ok {
					err := common.SetSecretFromRead(d, "api_key", "api_key_wo", "api_key_wo_version", password.(string))
					if err != nil {
						return err
					}
				}
				if appId, ok := value["application_id"]; ok {
					err := d.Set("app_id", appId.(string))
					if err != nil {
						return err
					}
				}
			case common.StorageAccountRotator:
				if username, ok := value["username"]; ok {
					err := d.Set("storage_account_key_name", username.(string))
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

func resourceRotatedSecretAzureUpdate(d *schema.ResourceData, m interface{}) error {

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
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	appId := d.Get("app_id").(string)
	apiId := d.Get("api_id").(string)
	apiKey, err := common.SecretValueForUpdate(d, "api_key", "api_key_wo")
	if err != nil {
		return err
	}
	storageAccountKeyName := d.Get("storage_account_key_name").(string)
	username := d.Get("username").(string)
	deleteProtection := d.Get("delete_protection").(string)
	explicitlySetSa := d.Get("explicitly_set_sa").(string)
	graceRotation := d.Get("grace_rotation").(string)
	graceRotationHour := d.Get("grace_rotation_hour").(int)
	graceRotationInterval := d.Get("grace_rotation_interval").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	maxVersions := d.Get("max_versions").(string)
	resourceGroupName := d.Get("resource_group_name").(string)
	resourceName := d.Get("resource_name").(string)
	rotateAfterDisconnect := d.Get("rotate_after_disconnect").(string)
	rotationEventInList := d.Get("rotation_event_in").([]interface{})
	rotationEventIn := common.ExpandStringList(rotationEventInList)
	secureAccessDisableConcurrentConnections := d.Get("secure_access_disable_concurrent_connections").(bool)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessUrl := d.Get("secure_access_url").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.RotatedSecretUpdateAzure{
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
	common.GetAkeylessPtr(&body.ApplicationId, appId)
	common.GetAkeylessPtr(&body.ApiId, apiId)
	common.SetOptionalString(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.StorageAccountKeyName, storageAccountKeyName)
	common.GetAkeylessPtr(&body.Username, username)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.ExplicitlySetSa, explicitlySetSa)
	common.GetAkeylessPtr(&body.GraceRotation, graceRotation)
	common.GetAkeylessPtr(&body.GraceRotationHour, graceRotationHour)
	common.GetAkeylessPtr(&body.GraceRotationInterval, graceRotationInterval)
	if len(itemCustomFields) > 0 {
		customFieldsMap := make(map[string]string)
		for k, v := range itemCustomFields {
			customFieldsMap[k] = v.(string)
		}
		body.ItemCustomFields = &customFieldsMap
	}
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.ResourceGroupName, resourceGroupName)
	common.GetAkeylessPtr(&body.ResourceName, resourceName)
	common.GetAkeylessPtr(&body.RotateAfterDisconnect, rotateAfterDisconnect)
	common.GetAkeylessPtr(&body.RotationEventIn, rotationEventIn)
	common.GetAkeylessPtr(&body.SecureAccessDisableConcurrentConnections, secureAccessDisableConcurrentConnections)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.RotatedSecretUpdateAzure(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretAzureDelete(d *schema.ResourceData, m interface{}) error {
	return resourceRotatedSecretCommonDelete(d, m)
}

func resourceRotatedSecretAzureImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceRotatedSecretAzureRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
