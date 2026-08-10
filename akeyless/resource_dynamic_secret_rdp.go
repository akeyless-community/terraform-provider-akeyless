// generated file
package akeyless

import (
	"context"
	"fmt"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceDynamicSecretRdp() *schema.Resource {
	return &schema.Resource{
		Description: "RDP dynamic secret resource",
		Create:      resourceDynamicSecretRdpCreate,
		Read:        resourceDynamicSecretRdpRead,
		Update:      resourceDynamicSecretRdpUpdate,
		Delete:      resourceDynamicSecretRdpDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretRdpImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("rdp_admin_pwd"), cty.GetAttrPath("rdp_admin_pwd_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Target name",
			},
			"rdp_user_groups": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Groups",
			},
			"rdp_host_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Hostname",
			},
			"rdp_admin_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "RDP Admin Name",
			},
			"rdp_admin_pwd": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "RDP Admin password",
			},
			"rdp_admin_pwd_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"rdp_admin_pwd_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "rdp_admin_pwd (write-only, not stored in state). Requires Terraform 1.11+. Bump rdp_admin_pwd_wo_version to change it.",
			},
			"rdp_admin_pwd_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"rdp_admin_pwd_wo"},
				Description:  "Version trigger for rdp_admin_pwd_wo. Increment to update the value.",
			},
			"rdp_host_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Port",
				Default:     "22",
			},
			"fixed_user_only": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Allow access using externally (IdP) provided username [true/false]",
				Default:     "false",
			},
			"fixed_user_claim_keyname": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "For externally provided users, denotes the key-name of IdP claim to extract the username from (relevant only for fixed-user-only=true)",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
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
			"encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Dynamic producer encryption key",
			},
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customize how temporary usernames are generated using go template",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
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
			"allow_user_extend_session": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Allow user to extend session",
			},
			"warn_user_before_expiration": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Warn user before expiration in minutes",
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_rdp_domain": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Required when the Dynamic Secret is used for a domain user",
			},
			"secure_access_rdp_user": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Override the RDP Domain username",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Target servers for connections (In case of Linked Target association, host(s) will inherit Linked Target hosts - Relevant only for Dynamic Secrets/producers)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_allow_external_user": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Allow providing external user for a domain users",
				Default:     false,
			},
			"secure_access_certificate_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Secure Access",
			},
			"secure_access_delay": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The delay duration, in seconds, to wait after generating just-in-time credentials. Accepted range: 0-120 seconds",
			},
			"secure_access_rd_gateway_server": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "RD Gateway server",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Enable Web Secure Remote Access",
			},
		},
	}
}

func resourceDynamicSecretRdpCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	rdpUserGroups := d.Get("rdp_user_groups").(string)
	rdpHostName := d.Get("rdp_host_name").(string)
	rdpAdminName := d.Get("rdp_admin_name").(string)
	rdpAdminPwd, err := common.EffectiveSecretValue(d, "rdp_admin_pwd", "rdp_admin_pwd_wo")
	if err != nil {
		return err
	}
	rdpHostPort := d.Get("rdp_host_port").(string)
	fixedUserOnly := d.Get("fixed_user_only").(string)
	fixedUserClaimKeyname := d.Get("fixed_user_claim_keyname").(string)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	allowUserExtendSession := d.Get("allow_user_extend_session").(int)
	warnUserBeforeExpiration := d.Get("warn_user_before_expiration").(int)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessRdpDomain := d.Get("secure_access_rdp_domain").(string)
	secureAccessRdpUser := d.Get("secure_access_rdp_user").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessAllowExternalUser := d.Get("secure_access_allow_external_user").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	secureAccessDelay := d.Get("secure_access_delay").(int)
	secureAccessRdGatewayServer := d.Get("secure_access_rd_gateway_server").(string)

	body := akeyless_api.DynamicSecretCreateRdp{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.RdpUserGroups, rdpUserGroups)
	common.GetAkeylessPtr(&body.RdpHostName, rdpHostName)
	common.GetAkeylessPtr(&body.RdpAdminName, rdpAdminName)
	common.GetAkeylessPtr(&body.RdpAdminPwd, rdpAdminPwd)
	common.GetAkeylessPtr(&body.RdpHostPort, rdpHostPort)
	common.GetAkeylessPtr(&body.FixedUserOnly, fixedUserOnly)
	common.GetAkeylessPtr(&body.FixedUserClaimKeyname, fixedUserClaimKeyname)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.ItemCustomFields, &itemCustomFields)
	common.GetAkeylessPtr(&body.AllowUserExtendSession, int64(allowUserExtendSession))
	common.GetAkeylessPtr(&body.WarnUserBeforeExpiration, int64(warnUserBeforeExpiration))
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessRdpDomain, secureAccessRdpDomain)
	common.GetAkeylessPtr(&body.SecureAccessRdpUser, secureAccessRdpUser)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessAllowExternalUser, secureAccessAllowExternalUser)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessDelay, int64(secureAccessDelay))
	common.GetAkeylessPtr(&body.SecureAccessRdGatewayServer, secureAccessRdGatewayServer)

	_, resp, err := client.DynamicSecretCreateRdp(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretRdpRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get dynamic secret value", res, err)
	}
	if rOut.FixedUserOnly != nil {
		err = d.Set("fixed_user_only", *rOut.FixedUserOnly)
		if err != nil {
			return err
		}
	}
	if rOut.UserTtl != nil {
		err = d.Set("user_ttl", *rOut.UserTtl)
		if err != nil {
			return err
		}
	}
	if rOut.Tags != nil {
		err = d.Set("tags", rOut.Tags)
		if err != nil {
			return err
		}
	}

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = common.SetDataByPrefixSlash(d, "target_name", targetName, d.Get("target_name").(string))
		if err != nil {
			return err
		}
	}
	if rOut.Groups != nil {
		err = d.Set("rdp_user_groups", *rOut.Groups)
		if err != nil {
			return err
		}
	}
	if rOut.HostName != nil {
		err = d.Set("rdp_host_name", *rOut.HostName)
		if err != nil {
			return err
		}
	}
	if rOut.AdminName != nil {
		err = d.Set("rdp_admin_name", *rOut.AdminName)
		if err != nil {
			return err
		}
	}
	if rOut.AdminPwd != nil {
		err = common.SetSecretFromRead(d, "rdp_admin_pwd", "rdp_admin_pwd_wo", "rdp_admin_pwd_wo_version", *rOut.AdminPwd)
		if err != nil {
			return err
		}
	}
	if rOut.HostPort != nil {
		err = d.Set("rdp_host_port", *rOut.HostPort)
		if err != nil {
			return err
		}
	}
	if rOut.DynamicSecretKey != nil {
		err = common.SetDataByPrefixSlash(d, "encryption_key_name", *rOut.DynamicSecretKey, d.Get("encryption_key_name").(string))
		if err != nil {
			return err
		}
	}

	if rOut.UsernameTemplate != nil {
		err = d.Set("custom_username_template", *rOut.UsernameTemplate)
		if err != nil {
			return err
		}
	}
	if rOut.Metadata != nil {
		err = d.Set("description", *rOut.Metadata)
		if err != nil {
			return err
		}
	}
	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}
	if len(rOut.ItemCustomFieldsDetails) > 0 {
		customFields := make(map[string]string)
		for _, field := range rOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		err = d.Set("item_custom_fields", customFields)
		if err != nil {
			return err
		}
	}
	if rOut.PasswordLength != nil {
		err = d.Set("password_length", fmt.Sprintf("%d", *rOut.PasswordLength))
		if err != nil {
			return err
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	if err = setAgenticRulesReadFields(d, rOut.AgenticRules); err != nil {
		return err
	}
	if err = setDynamicSecretPasswordPolicyReadFields(d, rOut); err != nil {
		return err
	}

	d.SetId(path)

	return nil
}

func resourceDynamicSecretRdpUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	rdpUserGroups := d.Get("rdp_user_groups").(string)
	rdpHostName := d.Get("rdp_host_name").(string)
	rdpAdminName := d.Get("rdp_admin_name").(string)
	rdpAdminPwd, err := common.SecretValueForUpdate(d, "rdp_admin_pwd", "rdp_admin_pwd_wo")
	if err != nil {
		return err
	}
	rdpHostPort := d.Get("rdp_host_port").(string)
	fixedUserOnly := d.Get("fixed_user_only").(string)
	fixedUserClaimKeyname := d.Get("fixed_user_claim_keyname").(string)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	allowUserExtendSession := d.Get("allow_user_extend_session").(int)
	warnUserBeforeExpiration := d.Get("warn_user_before_expiration").(int)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessRdpDomain := d.Get("secure_access_rdp_domain").(string)
	secureAccessRdpUser := d.Get("secure_access_rdp_user").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessAllowExternalUser := d.Get("secure_access_allow_external_user").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	secureAccessDelay := d.Get("secure_access_delay").(int)
	secureAccessRdGatewayServer := d.Get("secure_access_rd_gateway_server").(string)

	body := akeyless_api.DynamicSecretUpdateRdp{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.RdpUserGroups, rdpUserGroups)
	common.GetAkeylessPtr(&body.RdpHostName, rdpHostName)
	common.GetAkeylessPtr(&body.RdpAdminName, rdpAdminName)
	common.SetOptionalString(&body.RdpAdminPwd, rdpAdminPwd)
	common.GetAkeylessPtr(&body.RdpHostPort, rdpHostPort)
	common.GetAkeylessPtr(&body.FixedUserOnly, fixedUserOnly)
	common.GetAkeylessPtr(&body.FixedUserClaimKeyname, fixedUserClaimKeyname)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.ItemCustomFields, &itemCustomFields)
	common.GetAkeylessPtr(&body.AllowUserExtendSession, int64(allowUserExtendSession))
	common.GetAkeylessPtr(&body.WarnUserBeforeExpiration, int64(warnUserBeforeExpiration))
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessRdpDomain, secureAccessRdpDomain)
	common.GetAkeylessPtr(&body.SecureAccessRdpUser, secureAccessRdpUser)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessAllowExternalUser, secureAccessAllowExternalUser)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessDelay, int64(secureAccessDelay))
	common.GetAkeylessPtr(&body.SecureAccessRdGatewayServer, secureAccessRdGatewayServer)

	_, resp, err := client.DynamicSecretUpdateRdp(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretRdpDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretRdpImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretRdpRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
