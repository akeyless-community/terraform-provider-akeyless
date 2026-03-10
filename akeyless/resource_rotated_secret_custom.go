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
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"authentication_credentials": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The credentials to connect with use-self-creds/use-target-creds",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"enable_password_policy": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable password policy",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults",
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
			"timeout_sec": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum allowed time in seconds for the custom rotator to return the results",
			},
			"use_capital_letters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Password must contain capital letters [true/false]",
			},
			"use_lower_letters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Password must contain lower case letters [true/false]",
			},
			"use_numbers": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Password must contain numbers [true/false]",
			},
			"use_special_characters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Password must contain special characters [true/false]",
			},
		},
	}
}

func resourceRotatedSecretCustomCreate(d *schema.ResourceData, m interface{}) error {
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
	key := d.Get("key").(string)
	autoRotate := d.Get("auto_rotate").(string)
	rotationInterval := d.Get("rotation_interval").(string)
	rotationHour := d.Get("rotation_hour").(int)
	customPayload := d.Get("custom_payload").(string)
	authenticationCredentials := d.Get("authentication_credentials").(string)
	deleteProtection := d.Get("delete_protection").(string)
	enablePasswordPolicy := d.Get("enable_password_policy").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	maxVersions := d.Get("max_versions").(string)
	rotateAfterDisconnect := d.Get("rotate_after_disconnect").(string)
	rotationEventInList := d.Get("rotation_event_in").([]interface{})
	rotationEventIn := common.ExpandStringList(rotationEventInList)
	secureAccessAllowExternalUser := d.Get("secure_access_allow_external_user").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostList := d.Get("secure_access_host").([]interface{})
	secureAccessHost := common.ExpandStringList(secureAccessHostList)
	secureAccessRdpDomain := d.Get("secure_access_rdp_domain").(string)
	secureAccessRdpUser := d.Get("secure_access_rdp_user").(string)
	secureAccessSshUser := d.Get("secure_access_ssh_user").(string)
	secureAccessUrl := d.Get("secure_access_url").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)
	timeoutSec := d.Get("timeout_sec").(int)
	useCapitalLetters := d.Get("use_capital_letters").(string)
	useLowerLetters := d.Get("use_lower_letters").(string)
	useNumbers := d.Get("use_numbers").(string)
	useSpecialCharacters := d.Get("use_special_characters").(string)

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
	common.GetAkeylessPtr(&body.AuthenticationCredentials, authenticationCredentials)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.EnablePasswordPolicy, enablePasswordPolicy)
	if len(itemCustomFields) > 0 {
		customFieldsMap := make(map[string]string)
		for k, v := range itemCustomFields {
			customFieldsMap[k] = v.(string)
		}
		body.ItemCustomFields = &customFieldsMap
	}
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.RotateAfterDisconnect, rotateAfterDisconnect)
	common.GetAkeylessPtr(&body.RotationEventIn, rotationEventIn)
	common.GetAkeylessPtr(&body.SecureAccessAllowExternalUser, secureAccessAllowExternalUser)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessRdpDomain, secureAccessRdpDomain)
	common.GetAkeylessPtr(&body.SecureAccessRdpUser, secureAccessRdpUser)
	common.GetAkeylessPtr(&body.SecureAccessSshUser, secureAccessSshUser)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	if timeoutSec > 0 {
		body.TimeoutSec = akeyless_api.PtrInt64(int64(timeoutSec))
	}
	common.GetAkeylessPtr(&body.UseCapitalLetters, useCapitalLetters)
	common.GetAkeylessPtr(&body.UseLowerLetters, useLowerLetters)
	common.GetAkeylessPtr(&body.UseNumbers, useNumbers)
	common.GetAkeylessPtr(&body.UseSpecialCharacters, useSpecialCharacters)

	_, resp, err := client.RotatedSecretCreateCustom(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretCustomRead(d *schema.ResourceData, m interface{}) error {
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

	val, ok := rOut["value"]
	if ok {
		value, ok := val.(map[string]any)
		if ok {
			if payload, ok := value["payload"]; ok {
				err := d.Set("custom_payload", payload.(string))
				if err != nil {
					return err
				}
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceRotatedSecretCustomUpdate(d *schema.ResourceData, m interface{}) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

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
	authenticationCredentials := d.Get("authentication_credentials").(string)
	deleteProtection := d.Get("delete_protection").(string)
	enablePasswordPolicy := d.Get("enable_password_policy").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	keepPrevVersion := d.Get("keep_prev_version").(string)
	maxVersions := d.Get("max_versions").(string)
	rotateAfterDisconnect := d.Get("rotate_after_disconnect").(string)
	rotationEventInList := d.Get("rotation_event_in").([]interface{})
	rotationEventIn := common.ExpandStringList(rotationEventInList)
	secureAccessAllowExternalUser := d.Get("secure_access_allow_external_user").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostList := d.Get("secure_access_host").([]interface{})
	secureAccessHost := common.ExpandStringList(secureAccessHostList)
	secureAccessRdpDomain := d.Get("secure_access_rdp_domain").(string)
	secureAccessRdpUser := d.Get("secure_access_rdp_user").(string)
	secureAccessSshUser := d.Get("secure_access_ssh_user").(string)
	secureAccessUrl := d.Get("secure_access_url").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)
	timeoutSec := d.Get("timeout_sec").(int)
	useCapitalLetters := d.Get("use_capital_letters").(string)
	useLowerLetters := d.Get("use_lower_letters").(string)
	useNumbers := d.Get("use_numbers").(string)
	useSpecialCharacters := d.Get("use_special_characters").(string)

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
	common.GetAkeylessPtr(&body.AuthenticationCredentials, authenticationCredentials)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.EnablePasswordPolicy, enablePasswordPolicy)
	if len(itemCustomFields) > 0 {
		customFieldsMap := make(map[string]string)
		for k, v := range itemCustomFields {
			customFieldsMap[k] = v.(string)
		}
		body.ItemCustomFields = &customFieldsMap
	}
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.RotateAfterDisconnect, rotateAfterDisconnect)
	common.GetAkeylessPtr(&body.RotationEventIn, rotationEventIn)
	common.GetAkeylessPtr(&body.SecureAccessAllowExternalUser, secureAccessAllowExternalUser)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessRdpDomain, secureAccessRdpDomain)
	common.GetAkeylessPtr(&body.SecureAccessRdpUser, secureAccessRdpUser)
	common.GetAkeylessPtr(&body.SecureAccessSshUser, secureAccessSshUser)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	if timeoutSec > 0 {
		body.TimeoutSec = akeyless_api.PtrInt64(int64(timeoutSec))
	}
	common.GetAkeylessPtr(&body.UseCapitalLetters, useCapitalLetters)
	common.GetAkeylessPtr(&body.UseLowerLetters, useLowerLetters)
	common.GetAkeylessPtr(&body.UseNumbers, useNumbers)
	common.GetAkeylessPtr(&body.UseSpecialCharacters, useSpecialCharacters)

	_, resp, err := client.RotatedSecretUpdateCustom(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update rotated secret", resp, err)
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
