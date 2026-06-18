package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretLdap() *schema.Resource {
	return &schema.Resource{
		Description: "LDAP dynamic secret resource",
		Create:      resourceDynamicSecretLdapCreate,
		Read:        resourceDynamicSecretLdapRead,
		Update:      resourceDynamicSecretLdapUpdate,
		Delete:      resourceDynamicSecretLdapDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretLdapImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"provider_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Provider type",
			},
			"bind_dn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Bind DN",
			},
			"bind_dn_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Bind DN Password",
			},
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customize how temporary usernames are generated using go template",
			},
			"external_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Externally provided username [true/false]",
				Default:     "false",
			},
			"fixed_user_claim_keyname": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "For externally provided users, denotes the key-name of IdP claim to extract the username from (relevant only for external-username=true)",
				Default:     "ext_username",
			},
			"group_dn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Group DN which the temporary user should be added",
			},
			"host_provider": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Host provider type [explicit/target], Default Host provider is explicit, Relevant only for Secure Remote Access of ssh cert issuer, ldap rotated secret and ldap dynamic secret",
			},
			"ldap_ca_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "CA Certificate File Content",
			},
			"ldap_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "LDAP Server URL",
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
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access [true/false]",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Target servers for connections (In case of Linked Target association, host(s) will inherit Linked Target hosts - Relevant only for Dynamic Secrets/producers)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_rd_gateway_server": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "RD Gateway server",
			},
			"secure_access_rdp_domain": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Required when the Dynamic Secret is used for a domain user",
			},
			"target": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of linked targets to be associated, Relevant only for Secure Remote Access for ssh cert issuer, ldap rotated secret and ldap dynamic secret, To specify multiple targets use argument multiple times",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Target name",
			},
			"token_expiration": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Token expiration",
			},
			"user_attribute": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User Attribute",
			},
			"user_dn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User DN",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"producer_encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Dynamic producer encryption key",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceDynamicSecretLdapCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	providerType := d.Get("provider_type").(string)
	bindDn := d.Get("bind_dn").(string)
	bindDnPassword := d.Get("bind_dn_password").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	externalUsername := d.Get("external_username").(string)
	fixedUserClaimKeyname := d.Get("fixed_user_claim_keyname").(string)
	groupDn := d.Get("group_dn").(string)
	hostProvider := d.Get("host_provider").(string)
	ldapCaCert := d.Get("ldap_ca_cert").(string)
	ldapUrl := d.Get("ldap_url").(string)
	passwordLength := d.Get("password_length").(string)
	useCapitalLetters := d.Get("use_capital_letters").(string)
	useLowerLetters := d.Get("use_lower_letters").(string)
	useNumbers := d.Get("use_numbers").(string)
	useSpecialCharacters := d.Get("use_special_characters").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	secureAccessDelay := d.Get("secure_access_delay").(int)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessRdGatewayServer := d.Get("secure_access_rd_gateway_server").(string)
	secureAccessRdpDomain := d.Get("secure_access_rdp_domain").(string)
	targetSet := d.Get("target").(*schema.Set)
	target := common.ExpandStringList(targetSet.List())
	targetName := d.Get("target_name").(string)
	tokenExpiration := d.Get("token_expiration").(string)
	userAttribute := d.Get("user_attribute").(string)
	userDn := d.Get("user_dn").(string)
	userTtl := d.Get("user_ttl").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.GatewayCreateProducerLdap{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ProviderType, providerType)
	common.GetAkeylessPtr(&body.BindDn, bindDn)
	common.GetAkeylessPtr(&body.BindDnPassword, bindDnPassword)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.ExternalUsername, externalUsername)
	common.GetAkeylessPtr(&body.FixedUserClaimKeyname, fixedUserClaimKeyname)
	common.GetAkeylessPtr(&body.GroupDn, groupDn)
	common.GetAkeylessPtr(&body.HostProvider, hostProvider)
	common.GetAkeylessPtr(&body.LdapCaCert, ldapCaCert)
	common.GetAkeylessPtr(&body.LdapUrl, ldapUrl)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.UseCapitalLetters, useCapitalLetters)
	common.GetAkeylessPtr(&body.UseLowerLetters, useLowerLetters)
	common.GetAkeylessPtr(&body.UseNumbers, useNumbers)
	common.GetAkeylessPtr(&body.UseSpecialCharacters, useSpecialCharacters)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessDelay, int64(secureAccessDelay))
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessRdGatewayServer, secureAccessRdGatewayServer)
	common.GetAkeylessPtr(&body.SecureAccessRdpDomain, secureAccessRdpDomain)
	common.GetAkeylessPtr(&body.Target, target)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.TokenExpiration, tokenExpiration)
	common.GetAkeylessPtr(&body.UserAttribute, userAttribute)
	common.GetAkeylessPtr(&body.UserDn, userDn)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.GatewayCreateProducerLdap(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretLdapRead(d *schema.ResourceData, m interface{}) error {
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

	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}
	if rOut.Tags != nil {
		err = d.Set("tags", rOut.Tags)
		if err != nil {
			return err
		}
	}

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
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

	if rOut.DynamicSecretKey != nil {
		err = d.Set("producer_encryption_key_name", *rOut.DynamicSecretKey)
		if err != nil {
			return err
		}
	}

	if len(rOut.ItemCustomFieldsDetails) > 0 {
		customFields := make(map[string]string)
		for _, field := range rOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		if len(customFields) > 0 {
			err = d.Set("item_custom_fields", customFields)
			if err != nil {
				return err
			}
		}
	}

	if err = setAgenticRulesReadFields(d, rOut.AgenticRules); err != nil {
		return err
	}
	if err = setDynamicSecretPasswordPolicyReadFields(d, rOut); err != nil {
		return err
	}

	d.SetId(path)

	return nil
}

func resourceDynamicSecretLdapUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	providerType := d.Get("provider_type").(string)
	bindDn := d.Get("bind_dn").(string)
	bindDnPassword := d.Get("bind_dn_password").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	externalUsername := d.Get("external_username").(string)
	fixedUserClaimKeyname := d.Get("fixed_user_claim_keyname").(string)
	groupDn := d.Get("group_dn").(string)
	hostProvider := d.Get("host_provider").(string)
	ldapCaCert := d.Get("ldap_ca_cert").(string)
	ldapUrl := d.Get("ldap_url").(string)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	secureAccessDelay := d.Get("secure_access_delay").(int)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessRdGatewayServer := d.Get("secure_access_rd_gateway_server").(string)
	secureAccessRdpDomain := d.Get("secure_access_rdp_domain").(string)
	targetSet := d.Get("target").(*schema.Set)
	target := common.ExpandStringList(targetSet.List())
	targetName := d.Get("target_name").(string)
	tokenExpiration := d.Get("token_expiration").(string)
	userAttribute := d.Get("user_attribute").(string)
	userDn := d.Get("user_dn").(string)
	userTtl := d.Get("user_ttl").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.GatewayUpdateProducerLdap{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ProviderType, providerType)
	common.GetAkeylessPtr(&body.BindDn, bindDn)
	common.GetAkeylessPtr(&body.BindDnPassword, bindDnPassword)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.ExternalUsername, externalUsername)
	common.GetAkeylessPtr(&body.FixedUserClaimKeyname, fixedUserClaimKeyname)
	common.GetAkeylessPtr(&body.GroupDn, groupDn)
	common.GetAkeylessPtr(&body.HostProvider, hostProvider)
	common.GetAkeylessPtr(&body.LdapCaCert, ldapCaCert)
	common.GetAkeylessPtr(&body.LdapUrl, ldapUrl)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessDelay, int64(secureAccessDelay))
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessRdGatewayServer, secureAccessRdGatewayServer)
	common.GetAkeylessPtr(&body.SecureAccessRdpDomain, secureAccessRdpDomain)
	common.GetAkeylessPtr(&body.Target, target)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.TokenExpiration, tokenExpiration)
	common.GetAkeylessPtr(&body.UserAttribute, userAttribute)
	common.GetAkeylessPtr(&body.UserDn, userDn)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.GatewayUpdateProducerLdap(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretLdapDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretLdapImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretLdapRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
