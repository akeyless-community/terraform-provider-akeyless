// generated file
package akeyless

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceAuthMethodKerberos() *schema.Resource {
	return &schema.Resource{
		Description: "Kerberos Auth Method Resource",
		Create:      resourceAuthMethodKerberosCreate,
		Read:        resourceAuthMethodKerberosRead,
		Update:      resourceAuthMethodKerberosUpdate,
		Delete:      resourceAuthMethodKerberosDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodKerberosImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("keytab_file_data"), cty.GetAttrPath("keytab_file_data_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("bind_dn_password"), cty.GetAttrPath("bind_dn_password_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Auth Method name",
				ForceNew:         true,
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Auth Method description",
			},
			"access_expires": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Access expiration date in Unix timestamp (select 0 for access without expiry date)",
				Default:     0,
			},
			"allowed_client_type": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Limit the auth method usage for specific client types [cli,ui,gateway-admin,sdk,mobile,extension]",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_ips": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A comma-separated CIDR block list to allow client access",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"gw_bound_ips": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A comma-separated CIDR block list as a trusted Gateway entity",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"force_sub_claims": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "enforce role-association must include sub claims",
			},
			"jwt_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "creds expiration time in minutes. If not set, use default according to account settings (see get-account-settings)",
				Default:     0,
			},
			"product_type": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Choose the relevant product type for the auth method [sm, sra, pm, dp, ca]",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"audit_logs_claims": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Subclaims to include in audit logs",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"expiration_event_in": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "How many days before the expiration of the auth method would you like to be notified",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object, [true/false]",
				Default:     "false",
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
				Description: "Bind DN password",
			},
			"bind_dn_password_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"bind_dn_password_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "bind_dn_password (write-only, not stored in state). Requires Terraform 1.11+. Bump bind_dn_password_wo_version to change it.",
			},
			"bind_dn_password_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"bind_dn_password_wo"},
				Description:  "Version trigger for bind_dn_password_wo. Increment to update the value.",
			},
			"group_attr": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Group attribute",
			},
			"group_dn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Group DN",
			},
			"group_filter": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Group filter",
			},
			"keytab_file_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Keytab file data (base64 encoded)",
			},
			"keytab_file_data_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"keytab_file_data_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "keytab_file_data (write-only, not stored in state). Requires Terraform 1.11+. Bump keytab_file_data_wo_version to change it.",
			},
			"keytab_file_data_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"keytab_file_data_wo"},
				Description:  "Version trigger for keytab_file_data_wo. Increment to update the value.",
			},
			"krb5_conf_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Kerberos configuration file data (base64 encoded)",
			},
			"ldap_anonymous_search": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable LDAP anonymous search",
			},
			"ldap_ca_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "LDAP CA certificate",
			},
			"ldap_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "LDAP URL",
			},
			"unique_identifier": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A unique identifier (ID) value should be configured. Whenever a user logs in with a token, these authentication types issue a sub claim that contains details uniquely identifying that user. This sub claim includes a key containing the ID value that you configured, and is used to distinguish between different users from within the same organization.",
			},
			"user_attribute": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User attribute",
			},
			"user_dn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User DN",
			},
			"subclaims_delimiters": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of additional sub claims delimiters",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"access_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Auth Method access ID",
			},
		},
	}
}

func resourceAuthMethodKerberosCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	accessExpires := d.Get("access_expires").(int)
	allowedClientTypeSet := d.Get("allowed_client_type").(*schema.Set)
	allowedClientType := common.ExpandStringList(allowedClientTypeSet.List())
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	gwBoundIpsSet := d.Get("gw_bound_ips").(*schema.Set)
	gwBoundIps := common.ExpandStringList(gwBoundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	jwtTtl := d.Get("jwt_ttl").(int)
	productTypeSet := d.Get("product_type").(*schema.Set)
	productType := common.ExpandStringList(productTypeSet.List())
	auditLogsClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	auditLogsClaims := common.ExpandStringList(auditLogsClaimsSet.List())
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	bindDn := d.Get("bind_dn").(string)
	bindDnPassword, err := common.EffectiveSecretValue(d, "bind_dn_password", "bind_dn_password_wo")
	if err != nil {
		return err
	}
	groupAttr := d.Get("group_attr").(string)
	groupDn := d.Get("group_dn").(string)
	groupFilter := d.Get("group_filter").(string)
	keytabFileData, err := common.EffectiveSecretValue(d, "keytab_file_data", "keytab_file_data_wo")
	if err != nil {
		return err
	}
	krb5ConfData := d.Get("krb5_conf_data").(string)
	ldapAnonymousSearch := d.Get("ldap_anonymous_search").(bool)
	ldapCaCert := d.Get("ldap_ca_cert").(string)
	ldapUrl := d.Get("ldap_url").(string)
	uniqueIdentifier := d.Get("unique_identifier").(string)
	userAttribute := d.Get("user_attribute").(string)
	userDn := d.Get("user_dn").(string)
	subclaimsDelimitersSet := d.Get("subclaims_delimiters").(*schema.Set)
	subclaimsDelimiters := common.ExpandStringList(subclaimsDelimitersSet.List())

	body := akeyless_api.AuthMethodCreateKerberos{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.AllowedClientType, allowedClientType)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.ProductType, productType)
	common.GetAkeylessPtr(&body.AuditLogsClaims, auditLogsClaims)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.BindDn, bindDn)
	common.GetAkeylessPtr(&body.BindDnPassword, bindDnPassword)
	common.GetAkeylessPtr(&body.GroupAttr, groupAttr)
	common.GetAkeylessPtr(&body.GroupDn, groupDn)
	common.GetAkeylessPtr(&body.GroupFilter, groupFilter)
	common.GetAkeylessPtr(&body.KeytabFileData, keytabFileData)
	common.GetAkeylessPtr(&body.Krb5ConfData, krb5ConfData)
	common.GetAkeylessPtr(&body.LdapAnonymousSearch, ldapAnonymousSearch)
	common.GetAkeylessPtr(&body.LdapCaCert, ldapCaCert)
	common.GetAkeylessPtr(&body.LdapUrl, ldapUrl)
	common.GetAkeylessPtr(&body.UniqueIdentifier, uniqueIdentifier)
	common.GetAkeylessPtr(&body.UserAttribute, userAttribute)
	common.GetAkeylessPtr(&body.UserDn, userDn)
	common.GetAkeylessPtr(&body.SubclaimsDelimiters, subclaimsDelimiters)

	rOut, resp, err := client.AuthMethodCreateKerberos(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create auth method", resp, err)
	}

	if rOut.AccessId != nil {
		err = d.Set("access_id", *rOut.AccessId)
		if err != nil {
			return err
		}
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodKerberosRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.AuthMethodGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.AuthMethodGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get auth method", res, err)
	}

	if rOut.AuthMethodAccessId != nil {
		err = d.Set("access_id", *rOut.AuthMethodAccessId)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AccessExpires != nil {
		err = d.Set("access_expires", *rOut.AccessInfo.AccessExpires)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.ForceSubClaims != nil {
		err = d.Set("force_sub_claims", *rOut.AccessInfo.ForceSubClaims)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.CidrWhitelist != nil && *rOut.AccessInfo.CidrWhitelist != "" {
		err = d.Set("bound_ips", strings.Split(*rOut.AccessInfo.CidrWhitelist, ","))
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.GwCidrWhitelist != nil && *rOut.AccessInfo.GwCidrWhitelist != "" {
		err = d.Set("gw_bound_ips", strings.Split(*rOut.AccessInfo.GwCidrWhitelist, ","))
		if err != nil {
			return err
		}
	}

	if rOut.Description != nil {
		err = d.Set("description", *rOut.Description)
		if err != nil {
			return err
		}
	}

	rOutAcc, err := getAccountSettings(m)
	if err != nil {
		return err
	}
	jwtDefault := extractAccountJwtTtlDefault(rOutAcc)

	if rOut.AccessInfo.JwtTtl != nil {
		if *rOut.AccessInfo.JwtTtl != jwtDefault || d.Get("jwt_ttl").(int) != 0 {
			err = d.Set("jwt_ttl", *rOut.AccessInfo.JwtTtl)
			if err != nil {
				return err
			}
		}
	}

	if rOut.AccessInfo.ProductTypes != nil {
		productTypes := common.GetOriginalProductTypeConvention(d, rOut.AccessInfo.ProductTypes)
		err = d.Set("product_type", productTypes)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.AuditLogsClaims != nil {
		err = d.Set("audit_logs_claims", rOut.AccessInfo.AuditLogsClaims)
		if err != nil {
			return err
		}
	}

	if rOut.ExpirationEvents != nil {
		err := d.Set("expiration_event_in", common.ReadAuthExpirationEventInParam(rOut.ExpirationEvents))
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

	if rOut.AccessInfo.KerberosAccessRules != nil {
		if rOut.AccessInfo.KerberosAccessRules.UniqueIdentifier != nil {
			err = d.Set("unique_identifier", *rOut.AccessInfo.KerberosAccessRules.UniqueIdentifier)
			if err != nil {
				return err
			}
		}
	}

	if rOut.AuthMethodAdditionalData != nil && rOut.AuthMethodAdditionalData.KerberosData != nil {
		kd := rOut.AuthMethodAdditionalData.KerberosData
		if kd.LdapBindDn != nil {
			if err := d.Set("bind_dn", *kd.LdapBindDn); err != nil {
				return err
			}
		}
		if kd.LdapGroupAttr != nil {
			if err := d.Set("group_attr", *kd.LdapGroupAttr); err != nil {
				return err
			}
		}
		if kd.LdapGroupDn != nil {
			if err := d.Set("group_dn", *kd.LdapGroupDn); err != nil {
				return err
			}
		}
		if kd.LdapGroupFilter != nil {
			if err := d.Set("group_filter", *kd.LdapGroupFilter); err != nil {
				return err
			}
		}
		if kd.KerberosKrb5Conf != nil {
			if err := d.Set("krb5_conf_data", base64.StdEncoding.EncodeToString([]byte(*kd.KerberosKrb5Conf))); err != nil {
				return err
			}
		}
		if kd.LdapAnonymousSearch != nil {
			if err := d.Set("ldap_anonymous_search", *kd.LdapAnonymousSearch); err != nil {
				return err
			}
		}
		if kd.LdapCertificate != nil {
			if err := d.Set("ldap_ca_cert", *kd.LdapCertificate); err != nil {
				return err
			}
		}
		if kd.LdapUrlAddress != nil {
			if err := d.Set("ldap_url", *kd.LdapUrlAddress); err != nil {
				return err
			}
		}
		if kd.LdapUserAttr != nil {
			if err := d.Set("user_attribute", *kd.LdapUserAttr); err != nil {
				return err
			}
		}
		if kd.LdapUserDn != nil {
			if err := d.Set("user_dn", *kd.LdapUserDn); err != nil {
				return err
			}
		}
		if kd.LdapBindPassword != nil {
			if err := common.SetSecretFromRead(d, "bind_dn_password", "bind_dn_password_wo", "bind_dn_password_wo_version", *kd.LdapBindPassword); err != nil {
				return err
			}
		}
		if kd.KerberosKeytab != nil {
			if err := common.SetSecretFromRead(d, "keytab_file_data", "keytab_file_data_wo", "keytab_file_data_wo_version", *kd.KerberosKeytab); err != nil {
				return err
			}
		}
	}

	if len(rOut.AccessInfo.AllowedClientType) > 0 {
		// Only set allowed_client_type if it was explicitly configured by the user
		if _, ok := d.GetOk("allowed_client_type"); ok {
			err = d.Set("allowed_client_type", rOut.AccessInfo.AllowedClientType)
			if err != nil {
				return err
			}
		}
	}

	if rOut.AccessInfo.SubClaimsDelimiters != nil {
		err = d.Set("subclaims_delimiters", rOut.AccessInfo.SubClaimsDelimiters)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceAuthMethodKerberosUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	accessExpires := d.Get("access_expires").(int)
	allowedClientTypeSet := d.Get("allowed_client_type").(*schema.Set)
	allowedClientType := common.ExpandStringList(allowedClientTypeSet.List())
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	gwBoundIpsSet := d.Get("gw_bound_ips").(*schema.Set)
	gwBoundIps := common.ExpandStringList(gwBoundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	jwtTtl := d.Get("jwt_ttl").(int)
	productTypeSet := d.Get("product_type").(*schema.Set)
	productType := common.ExpandStringList(productTypeSet.List())
	auditLogsClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	auditLogsClaims := common.ExpandStringList(auditLogsClaimsSet.List())
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	bindDn := d.Get("bind_dn").(string)
	bindDnPassword, err := common.SecretValueForUpdate(d, "bind_dn_password", "bind_dn_password_wo")
	if err != nil {
		return err
	}
	groupAttr := d.Get("group_attr").(string)
	groupDn := d.Get("group_dn").(string)
	groupFilter := d.Get("group_filter").(string)
	keytabFileData, err := common.SecretValueForUpdate(d, "keytab_file_data", "keytab_file_data_wo")
	if err != nil {
		return err
	}
	krb5ConfData := d.Get("krb5_conf_data").(string)
	ldapAnonymousSearch := d.Get("ldap_anonymous_search").(bool)
	ldapCaCert := d.Get("ldap_ca_cert").(string)
	ldapUrl := d.Get("ldap_url").(string)
	uniqueIdentifier := d.Get("unique_identifier").(string)
	userAttribute := d.Get("user_attribute").(string)
	userDn := d.Get("user_dn").(string)
	subclaimsDelimitersSet := d.Get("subclaims_delimiters").(*schema.Set)
	subclaimsDelimiters := common.ExpandStringList(subclaimsDelimitersSet.List())

	body := akeyless_api.AuthMethodUpdateKerberos{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.AllowedClientType, allowedClientType)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.ProductType, productType)
	common.GetAkeylessPtr(&body.AuditLogsClaims, auditLogsClaims)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.BindDn, bindDn)
	common.SetOptionalString(&body.BindDnPassword, bindDnPassword)
	common.GetAkeylessPtr(&body.GroupAttr, groupAttr)
	common.GetAkeylessPtr(&body.GroupDn, groupDn)
	common.GetAkeylessPtr(&body.GroupFilter, groupFilter)
	common.SetOptionalString(&body.KeytabFileData, keytabFileData)
	common.GetAkeylessPtr(&body.Krb5ConfData, krb5ConfData)
	common.GetAkeylessPtr(&body.LdapAnonymousSearch, ldapAnonymousSearch)
	common.GetAkeylessPtr(&body.LdapCaCert, ldapCaCert)
	common.GetAkeylessPtr(&body.LdapUrl, ldapUrl)
	common.GetAkeylessPtr(&body.UniqueIdentifier, uniqueIdentifier)
	common.GetAkeylessPtr(&body.UserAttribute, userAttribute)
	common.GetAkeylessPtr(&body.UserDn, userDn)
	common.GetAkeylessPtr(&body.SubclaimsDelimiters, subclaimsDelimiters)

	_, resp, err := client.AuthMethodUpdateKerberos(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update auth method", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodKerberosDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.AuthMethodDelete{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.AuthMethodDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceAuthMethodKerberosImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAuthMethodKerberosRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
