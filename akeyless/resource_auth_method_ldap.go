// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"net/http"
	"strconv"
	"strings"
)

func resourceAuthMethodLdap() *schema.Resource {
	return &schema.Resource{
		Description: "LDAP Auth Method Resource",
		Create:      resourceAuthMethodLdapCreate,
		Read:        resourceAuthMethodLdapRead,
		Update:      resourceAuthMethodLdapUpdate,
		Delete:      resourceAuthMethodLdapDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodLdapImport,
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
				Default:     "0",
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
			"public_key_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "A public key generated for LDAP authentication method on Akeyless [RSA2048] in Base64 or PEM format",
			},
			"unique_identifier": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A unique identifier (ID) value should be configured for LDAP, OAuth2 and SAML authentication method types and is usually a value such as the email, username, or upn for example. Whenever a user logs in with a token, these authentication types issue a sub claim that contains details uniquely identifying that user. This sub claim includes a key containing the ID value that you configured, and is used to distinguish between different users from within the same organization.",
				Default:     "users",
			},
			"gen_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Automatically generate key-pair for LDAP configuration. If set to false, a public key needs to be provided",
				Default:     "true",
			},
			"access_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Auth Method access ID",
			},
			"private_key_data": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Private key data in Base64 format. This is only returned if the gen_key parameter is set to true.",
			},
		},
	}
}

func resourceAuthMethodLdapCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	accessExpires := d.Get("access_expires").(int)
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
	publicKeyData := d.Get("public_key_data").(string)
	uniqueIdentifier := d.Get("unique_identifier").(string)
	genKey := d.Get("gen_key").(string)

	body := akeyless_api.AuthMethodCreateLdap{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.ProductType, productType)
	common.GetAkeylessPtr(&body.AuditLogsClaims, auditLogsClaims)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.PublicKeyData, publicKeyData)
	common.GetAkeylessPtr(&body.UniqueIdentifier, uniqueIdentifier)
	common.GetAkeylessPtr(&body.GenKey, genKey)

	rOut, resp, err := client.AuthMethodCreateLdap(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create auth method ldap", resp, err)
	}

	if rOut.AccessId != nil {
		err = d.Set("access_id", *rOut.AccessId)
		if err != nil {
			return err
		}
	}

	if rOut.PrvKey != nil {
		err = d.Set("private_key_data", *rOut.PrvKey)
		if err != nil {
			return err
		}
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodLdapRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	name := d.Id()

	body := akeyless_api.AuthMethodGet{
		Name:  name,
		Token: &token,
	}

	rOut, res, err := client.AuthMethodGet(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("failed to get value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to get value: %v", err)
	}

	if rOut.Description != nil {
		err = d.Set("description", *rOut.Description)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo != nil {
		if rOut.AccessInfo.AccessExpires != nil {
			err = d.Set("access_expires", *rOut.AccessInfo.AccessExpires)
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

		if rOut.AccessInfo.ForceSubClaims != nil {
			err = d.Set("force_sub_claims", *rOut.AccessInfo.ForceSubClaims)
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
		if rOut.AccessInfo.LdapAccessRules != nil {
			if rOut.AccessInfo.LdapAccessRules.UniqueIdentifier != nil {
				err = d.Set("unique_identifier", *rOut.AccessInfo.LdapAccessRules.UniqueIdentifier)
				if err != nil {
					return err
				}
			}
			if rOut.AccessInfo.LdapAccessRules.Key != nil {
				err = d.Set("public_key_data", *rOut.AccessInfo.LdapAccessRules.Key)
				if err != nil {
					return err
				}
			}
			if rOut.AccessInfo.LdapAccessRules.GenKeyPair != nil {
				err = d.Set("gen_key", *rOut.AccessInfo.LdapAccessRules.GenKeyPair)
				if err != nil {
					return err
				}
			}
		}
	}

	if rOut.DeleteProtection != nil {
		err = d.Set("delete_protection", strconv.FormatBool(*rOut.DeleteProtection))
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

	d.SetId(name)

	return nil
}

func resourceAuthMethodLdapUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	accessExpires := d.Get("access_expires").(int)
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
	publicKeyData := d.Get("public_key_data").(string)
	uniqueIdentifier := d.Get("unique_identifier").(string)
	genKey := d.Get("gen_key").(string)

	body := akeyless_api.AuthMethodUpdateLdap{
		Name:             name,
		UniqueIdentifier: &uniqueIdentifier,
		Token:            &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.ProductType, productType)
	common.GetAkeylessPtr(&body.AuditLogsClaims, auditLogsClaims)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.PublicKeyData, publicKeyData)
	common.GetAkeylessPtr(&body.GenKey, genKey)

	rOut, resp, err := client.AuthMethodUpdateLdap(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update auth method ldap", resp, err)
	}

	if rOut.PrvKey != nil {
		err = d.Set("private_key_data", *rOut.PrvKey)
		if err != nil {
			return err
		}
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodLdapDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceAuthMethodLdapImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAuthMethodLdapRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
