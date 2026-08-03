// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceGatewayUpdateLdapAuthConfig() *schema.Resource {
	return &schema.Resource{
		Description:   "LDAP auth config for gateway",
		Create:        resourceGatewayUpdateLdapAuthConfigUpdate,
		Read:          resourceGatewayUpdateLdapAuthConfigRead,
		Update:        resourceGatewayUpdateLdapAuthConfigUpdate,
		DeleteContext: resourceGatewayUpdateLdapAuthConfigDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateLdapAuthConfigImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("bind_dn_password"), cty.GetAttrPath("bind_dn_password_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("signing_key_data"), cty.GetAttrPath("signing_key_data_wo")),
		},
		Schema: map[string]*schema.Schema{
			"ldap_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable LDAP auth [true/false]",
			},
			"access_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The access ID of the auth method associated with the LDAP config",
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
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "Bind DN password (write-only, not stored in state). Requires Terraform 1.11+. Bump bind_dn_password_wo_version to change it.",
			},
			"bind_dn_password_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for bind_dn_password_wo. Increment to update the value.",
			},
			"group_attr": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "LDAP attribute to follow on objects returned by ldap_group_filter in order to enumerate user group membership",
			},
			"group_dn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base DN to perform group membership search",
			},
			"group_filter": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Go template used when constructing the group membership query. The template can access the following context variables: [UserDN, Username]",
			},
			"ldap_ca_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "LDAP CA Certificate (base64 encoded)",
			},
			"ldap_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "LDAP server URL",
			},
			"signing_key_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: " The private key (base64 encoded), associated with the public key defined in the Ldap auth",
			},
			"signing_key_data_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: " The private key (base64 encoded), associated with the public key defined in the Ldap auth (write-only, not stored in state). Requires Terraform 1.11+. Bump signing_key_data_wo_version to change it.",
			},
			"signing_key_data_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for signing_key_data_wo. Increment to update the value.",
			},
			"user_attribute": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "LDAP user attribute",
			},
			"user_dn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "LDAP user DN",
			},
		},
	}
}

func resourceGatewayUpdateLdapAuthConfigUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	ldapEnable := d.Get("ldap_enable").(string)
	accessId := d.Get("access_id").(string)
	bindDn := d.Get("bind_dn").(string)
	bindDnPassword, err := common.EffectiveSecretValue(d, "bind_dn_password", "bind_dn_password_wo")
	if err != nil {
		return err
	}
	groupAttr := d.Get("group_attr").(string)
	groupDn := d.Get("group_dn").(string)
	groupFilter := d.Get("group_filter").(string)
	ldapCaCert := d.Get("ldap_ca_cert").(string)
	ldapUrl := d.Get("ldap_url").(string)
	signingKeyData, err := common.EffectiveSecretValue(d, "signing_key_data", "signing_key_data_wo")
	if err != nil {
		return err
	}
	userAttribute := d.Get("user_attribute").(string)
	userDn := d.Get("user_dn").(string)

	body := akeyless_api.GatewayUpdateLdapAuthConfig{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.LdapEnable, ldapEnable)
	common.GetAkeylessPtr(&body.AccessId, accessId)
	common.GetAkeylessPtr(&body.BindDn, bindDn)
	common.GetAkeylessPtr(&body.BindDnPassword, bindDnPassword)
	common.GetAkeylessPtr(&body.GroupAttr, groupAttr)
	common.GetAkeylessPtr(&body.GroupDn, groupDn)
	common.GetAkeylessPtr(&body.GroupFilter, groupFilter)
	common.GetAkeylessPtr(&body.LdapCaCert, ldapCaCert)
	common.GetAkeylessPtr(&body.LdapUrl, ldapUrl)
	common.GetAkeylessPtr(&body.SigningKeyData, signingKeyData)
	common.GetAkeylessPtr(&body.UserAttribute, userAttribute)
	common.GetAkeylessPtr(&body.UserDn, userDn)

	_, resp, err := client.GatewayUpdateLdapAuthConfig(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update LDAP auth config", resp, err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGatewayUpdateLdapAuthConfigRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	body := akeyless_api.GatewayGetLdapAuthConfig{
		Token: &token,
	}

	rOut, resp, err := client.GatewayGetLdapAuthConfig(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't get LDAP auth config", resp, err)
	}

	if rOut.LdapEnable != nil {
		err = d.Set("ldap_enable", strconv.FormatBool(*rOut.LdapEnable))
		if err != nil {
			return err
		}
	}
	if rOut.LdapAccessId != nil {
		err = d.Set("access_id", *rOut.LdapAccessId)
		if err != nil {
			return err
		}
	}
	if rOut.LdapBindDn != nil {
		err = d.Set("bind_dn", *rOut.LdapBindDn)
		if err != nil {
			return err
		}
	}
	if rOut.LdapBindPassword != nil {
		err = common.SetSecretFromRead(d, "bind_dn_password", "bind_dn_password_wo", "bind_dn_password_wo_version", *rOut.LdapBindPassword)
		if err != nil {
			return err
		}
	}
	if rOut.LdapGroupAttr != nil {
		err = d.Set("group_attr", *rOut.LdapGroupAttr)
		if err != nil {
			return err
		}
	}
	if rOut.LdapGroupDn != nil {
		err = d.Set("group_dn", *rOut.LdapGroupDn)
		if err != nil {
			return err
		}
	}
	if rOut.LdapGroupFilter != nil {
		err = d.Set("group_filter", *rOut.LdapGroupFilter)
		if err != nil {
			return err
		}
	}
	if rOut.LdapUrl != nil {
		err = d.Set("ldap_url", *rOut.LdapUrl)
		if err != nil {
			return err
		}
	}
	if rOut.LdapUserAttr != nil {
		err = d.Set("user_attribute", *rOut.LdapUserAttr)
		if err != nil {
			return err
		}
	}
	if rOut.LdapUserDn != nil {
		err = d.Set("user_dn", *rOut.LdapUserDn)
		if err != nil {
			return err
		}
	}
	// signing_key_data and ldap_ca_cert are masked in the response.

	return nil
}

func resourceGatewayUpdateLdapAuthConfigDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateLdapAuthConfigImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	err := resourceGatewayUpdateLdapAuthConfigRead(d, m)
	if err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
