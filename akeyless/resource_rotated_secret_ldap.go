package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRotatedSecretLdap() *schema.Resource {
	return &schema.Resource{
		Description: "Ldap rotated secret resource",
		Create:      resourceRotatedSecretLdapCreate,
		Read:        resourceRotatedSecretLdapRead,
		Update:      resourceRotatedSecretLdapUpdate,
		Delete:      resourceRotatedSecretLdapDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRotatedSecretLdapImport,
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
				Description: "The rotator type. options: [target/ldap]",
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
				Description: "username to be rotated, if selected use-self-creds at rotator-creds-type, this username will try to rotate it's own password, if use-target-creds is selected, target credentials will be use to rotate the rotated-password (relevant only for rotator-type=ldap)",
			},
			"rotated_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "rotated-username password (relevant only for rotator-type=ldap)",
			},
			"user_dn": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Base DN to Perform User Search",
			},
			"user_attribute": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "LDAP User Attribute, Default value \"cn\"",
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
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"host_provider": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Host provider type [explicit/target], Default Host provider is explicit, Relevant only for Secure Remote Access of ssh cert issuer, ldap rotated secret and ldap dynamic secret",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
			"rotate_after_disconnect": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Rotate the value of the secret after SRA session ends [true/false]",
				Default:     "false",
			},
			"rotation_event_in": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "How many days before the rotation of the item would you like to be notified",
				Elem:        &schema.Schema{Type: schema.TypeString},
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
			"secure_access_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Destination URL to inject secrets",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable Web Secure Remote Access",
				Default:     false,
			},
			"secure_access_web_browsing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Secure browser via Akeyless's Secure Remote Access (SRA)",
				Default:     false,
			},
			"secure_access_web_proxy": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Web-Proxy via Akeyless's Secure Remote Access (SRA)",
				Default:     false,
			},
			"secure_access_certificate_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Secure Access",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"target": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A list of linked targets to be associated, Relevant only for Secure Remote Access for ssh cert issuer, ldap rotated secret and ldap dynamic secret, To specify multiple targets use argument multiple times",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceRotatedSecretLdapCreate(d *schema.ResourceData, m interface{}) error {
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
	rotatorType := d.Get("rotator_type").(string)
	authenticationCredentials := d.Get("authentication_credentials").(string)
	rotatedUsername := d.Get("rotated_username").(string)
	rotatedPassword := d.Get("rotated_password").(string)
	userDn := d.Get("user_dn").(string)
	userAttribute := d.Get("user_attribute").(string)
	deleteProtection := d.Get("delete_protection").(string)
	hostProvider := d.Get("host_provider").(string)
	maxVersions := d.Get("max_versions").(string)
	// keepPrevVersion is not available in RotatedSecretCreateLdap, only in RotatedSecretUpdateLdap
	rotateAfterDisconnect := d.Get("rotate_after_disconnect").(string)
	rotationEventIn := d.Get("rotation_event_in").([]interface{})
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHost := d.Get("secure_access_host").([]interface{})
	secureAccessRdpDomain := d.Get("secure_access_rdp_domain").(string)
	secureAccessUrl := d.Get("secure_access_url").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	target := d.Get("target").([]interface{})

	body := akeyless_api.RotatedSecretCreateLdap{
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
	common.GetAkeylessPtr(&body.UserDn, userDn)
	common.GetAkeylessPtr(&body.UserAttribute, userAttribute)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.HostProvider, hostProvider)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	// KeepPrevVersion is not available in RotatedSecretCreateLdap, only in RotatedSecretUpdateLdap
	common.GetAkeylessPtr(&body.RotateAfterDisconnect, rotateAfterDisconnect)
	common.GetAkeylessPtr(&body.RotationEventIn, common.ExpandStringList(rotationEventIn))
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, common.ExpandStringList(secureAccessHost))
	common.GetAkeylessPtr(&body.SecureAccessRdpDomain, secureAccessRdpDomain)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	if len(itemCustomFields) > 0 {
		customFieldsMap := make(map[string]string)
		for k, v := range itemCustomFields {
			customFieldsMap[k] = v.(string)
		}
		common.GetAkeylessPtr(&body.ItemCustomFields, customFieldsMap)
	}
	common.GetAkeylessPtr(&body.Target, common.ExpandStringList(target))

	_, resp, err := client.RotatedSecretCreateLdap(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretLdapRead(d *schema.ResourceData, m interface{}) error {
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
			err = setRotatorType(d, *rsd.RotatorType)
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
			case common.LdapRotator:
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

				// TODO: ldap payload is removed in gateway and we can't get it.
				//
				// if userDn, ok := value["ldap_user_dn"]; ok {
				// 	err := d.Set("user_dn", userDn.(string))
				// 	if err != nil {
				// 		return err
				// 	}
				// }
				// if userAttr, ok := value["ldap_user_attr"]; ok {
				// 	err := d.Set("user_attribute", userAttr.(string))
				// 	if err != nil {
				// 		return err
				// 	}
				// }
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

func resourceRotatedSecretLdapUpdate(d *schema.ResourceData, m interface{}) error {

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
	authenticationCredentials := d.Get("authentication_credentials").(string)
	rotatedUsername := d.Get("rotated_username").(string)
	rotatedPassword := d.Get("rotated_password").(string)
	userDn := d.Get("user_dn").(string)
	userAttribute := d.Get("user_attribute").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	hostProvider := d.Get("host_provider").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)
	rotateAfterDisconnect := d.Get("rotate_after_disconnect").(string)
	rotationEventIn := d.Get("rotation_event_in").([]interface{})
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHost := d.Get("secure_access_host").([]interface{})
	secureAccessRdpDomain := d.Get("secure_access_rdp_domain").(string)
	secureAccessUrl := d.Get("secure_access_url").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	target := d.Get("target").([]interface{})

	body := akeyless_api.RotatedSecretUpdateLdap{
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
	common.GetAkeylessPtr(&body.RotatedPassword, rotatedPassword)
	common.GetAkeylessPtr(&body.UserDn, userDn)
	common.GetAkeylessPtr(&body.UserAttribute, userAttribute)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.HostProvider, hostProvider)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)
	common.GetAkeylessPtr(&body.RotateAfterDisconnect, rotateAfterDisconnect)
	common.GetAkeylessPtr(&body.RotationEventIn, common.ExpandStringList(rotationEventIn))
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, common.ExpandStringList(secureAccessHost))
	common.GetAkeylessPtr(&body.SecureAccessRdpDomain, secureAccessRdpDomain)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	if len(itemCustomFields) > 0 {
		customFieldsMap := make(map[string]string)
		for k, v := range itemCustomFields {
			customFieldsMap[k] = v.(string)
		}
		common.GetAkeylessPtr(&body.ItemCustomFields, customFieldsMap)
	}
	common.GetAkeylessPtr(&body.Target, common.ExpandStringList(target))

	_, resp, err := client.RotatedSecretUpdateLdap(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update rotated secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceRotatedSecretLdapDelete(d *schema.ResourceData, m interface{}) error {
	return resourceRotatedSecretCommonDelete(d, m)
}

func resourceRotatedSecretLdapImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceRotatedSecretLdapRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
