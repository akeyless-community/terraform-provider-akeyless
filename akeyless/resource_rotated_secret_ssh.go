package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRotatedSecretSsh() *schema.Resource {
	return &schema.Resource{
		Description: "Ssh rotated secret resource",
		Create:      resourceRotatedSecretSshCreate,
		Read:        resourceRotatedSecretSshRead,
		Update:      resourceRotatedSecretSshUpdate,
		Delete:      resourceRotatedSecretSshDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRotatedSecretSshImport,
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
				Description: "username to be rotated, if selected use-self-creds at rotator-creds-type, this username will try to rotate it's own password, if use-target-creds is selected, target credentials will be use to rotate the rotated-password (relevant only for rotator-type=password)",
			},
			"rotated_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "rotated-username password (relevant only for rotator-type=password)",
			},
			"rotator_custom_cmd": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Custom rotation command",
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
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key_data_base64": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Private key file contents encoded using base64",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults",
			},
			"public_key_remote_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The path to the public key that will be rotated on the server",
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
			"same_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Rotate same password for each host from the Linked Target (relevant only for Linked Target)",
			},
			"secure_access_allow_external_user": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Allow providing external user for a domain users",
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
			"secure_access_host": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Target servers for connections (In case of Linked Target association, host(s) will inherit Linked Target hosts - Relevant only for Dynamic Secrets/producers)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_rdp_domain": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Default domain name server. i.e. microsoft.com",
			},
			"secure_access_rdp_user": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Override the RDP Domain username",
			},
			"secure_access_ssh_user": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Override the SSH username as indicated in SSH Certificate Issuer",
			},
			"secure_access_target_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specify target type. Options are ssh or rdp",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceRotatedSecretSshCreate(d *schema.ResourceData, m interface{}) error {
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
	rotatedPassword := d.Get("rotated_password").(string)
	rotatorCustomCmd := d.Get("rotator_custom_cmd").(string)
	deleteProtection := d.Get("delete_protection").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	keyDataBase64 := d.Get("key_data_base64").(string)
	maxVersions := d.Get("max_versions").(string)
	publicKeyRemotePath := d.Get("public_key_remote_path").(string)
	rotateAfterDisconnect := d.Get("rotate_after_disconnect").(string)
	rotationEventInList := d.Get("rotation_event_in").([]interface{})
	rotationEventIn := make([]string, len(rotationEventInList))
	for i, v := range rotationEventInList {
		rotationEventIn[i] = v.(string)
	}
	samePassword := d.Get("same_password").(string)
	secureAccessAllowExternalUser := d.Get("secure_access_allow_external_user").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostList := d.Get("secure_access_host").([]interface{})
	secureAccessHost := make([]string, len(secureAccessHostList))
	for i, v := range secureAccessHostList {
		secureAccessHost[i] = v.(string)
	}
	secureAccessRdpDomain := d.Get("secure_access_rdp_domain").(string)
	secureAccessRdpUser := d.Get("secure_access_rdp_user").(string)
	secureAccessSshUser := d.Get("secure_access_ssh_user").(string)
	secureAccessTargetType := d.Get("secure_access_target_type").(string)

	body := akeyless_api.RotatedSecretCreateSsh{
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
	common.GetAkeylessPtr(&body.RotatorCustomCmd, rotatorCustomCmd)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	if len(itemCustomFields) > 0 {
		body.ItemCustomFields = &itemCustomFields
	}
	common.GetAkeylessPtr(&body.KeyDataBase64, keyDataBase64)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.PublicKeyRemotePath, publicKeyRemotePath)
	common.GetAkeylessPtr(&body.RotateAfterDisconnect, rotateAfterDisconnect)
	if len(rotationEventIn) > 0 {
		body.RotationEventIn = rotationEventIn
	}
	common.GetAkeylessPtr(&body.SamePassword, samePassword)
	body.SecureAccessAllowExternalUser = &secureAccessAllowExternalUser
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	if len(secureAccessHost) > 0 {
		body.SecureAccessHost = secureAccessHost
	}
	common.GetAkeylessPtr(&body.SecureAccessRdpDomain, secureAccessRdpDomain)
	common.GetAkeylessPtr(&body.SecureAccessRdpUser, secureAccessRdpUser)
	common.GetAkeylessPtr(&body.SecureAccessSshUser, secureAccessSshUser)
	common.GetAkeylessPtr(&body.SecureAccessTargetType, secureAccessTargetType)

	_, resp, err := client.RotatedSecretCreateSsh(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretSshRead(d *schema.ResourceData, m interface{}) error {
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
		if rsd.RotationStatement != nil {
			err = d.Set("rotator_custom_cmd", *rsd.RotationStatement)
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
					err := d.Set("rotated_username", username.(string))
					if err != nil {
						return err
					}
				}
				if password, ok := value["password"]; ok {
					err := d.Set("rotated_password", password.(string))
					if err != nil {
						return err
					}
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

	d.SetId(path)

	return nil
}

func resourceRotatedSecretSshUpdate(d *schema.ResourceData, m interface{}) error {

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
	rotatedPassword := d.Get("rotated_password").(string)
	rotatorCustomCmd := d.Get("rotator_custom_cmd").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	keyDataBase64 := d.Get("key_data_base64").(string)
	maxVersions := d.Get("max_versions").(string)
	publicKeyRemotePath := d.Get("public_key_remote_path").(string)
	rotateAfterDisconnect := d.Get("rotate_after_disconnect").(string)
	rotationEventInList := d.Get("rotation_event_in").([]interface{})
	rotationEventIn := make([]string, len(rotationEventInList))
	for i, v := range rotationEventInList {
		rotationEventIn[i] = v.(string)
	}
	samePassword := d.Get("same_password").(string)
	secureAccessAllowExternalUser := d.Get("secure_access_allow_external_user").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostList := d.Get("secure_access_host").([]interface{})
	secureAccessHost := make([]string, len(secureAccessHostList))
	for i, v := range secureAccessHostList {
		secureAccessHost[i] = v.(string)
	}
	secureAccessRdpDomain := d.Get("secure_access_rdp_domain").(string)
	secureAccessRdpUser := d.Get("secure_access_rdp_user").(string)
	secureAccessSshUser := d.Get("secure_access_ssh_user").(string)
	secureAccessTargetType := d.Get("secure_access_target_type").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)
	rotatorType := d.Get("rotator_type").(string)

	body := akeyless_api.RotatedSecretUpdateSsh{
		Name:        name,
		NewName:     akeyless_api.PtrString(name),
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
	common.GetAkeylessPtr(&body.RotatorCustomCmd, rotatorCustomCmd)
	common.GetAkeylessPtr(&body.RotatedUsername, rotatedUsername)
	common.GetAkeylessPtr(&body.RotatedPassword, rotatedPassword)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	if len(itemCustomFields) > 0 {
		body.ItemCustomFields = &itemCustomFields
	}
	common.GetAkeylessPtr(&body.KeyDataBase64, keyDataBase64)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.PublicKeyRemotePath, publicKeyRemotePath)
	common.GetAkeylessPtr(&body.RotateAfterDisconnect, rotateAfterDisconnect)
	if len(rotationEventIn) > 0 {
		body.RotationEventIn = rotationEventIn
	}
	common.GetAkeylessPtr(&body.SamePassword, samePassword)
	body.SecureAccessAllowExternalUser = &secureAccessAllowExternalUser
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	if len(secureAccessHost) > 0 {
		body.SecureAccessHost = secureAccessHost
	}
	common.GetAkeylessPtr(&body.SecureAccessRdpDomain, secureAccessRdpDomain)
	common.GetAkeylessPtr(&body.SecureAccessRdpUser, secureAccessRdpUser)
	common.GetAkeylessPtr(&body.SecureAccessSshUser, secureAccessSshUser)
	common.GetAkeylessPtr(&body.SecureAccessTargetType, secureAccessTargetType)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.RotatedSecretUpdateSsh(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretSshDelete(d *schema.ResourceData, m interface{}) error {
	return resourceRotatedSecretCommonDelete(d, m)
}

func resourceRotatedSecretSshImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceRotatedSecretSshRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
