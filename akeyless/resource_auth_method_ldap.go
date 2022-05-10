// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
				Type:        schema.TypeString,
				Required:    true,
				Description: "Auth Method name",
				ForceNew:    true,
			},
			"access_expires": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Access expiration date in Unix timestamp (select 0 for access without expiry date)",
				Default:     "0",
			},
			"bound_ips": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "A CIDR whitelist with the IPs that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"force_sub_claims": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "enforce role-association must include sub claims",
			},
			"jwt_ttl": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "creds expiration time in minutes. If not set, use default according to account settings (see get-account-settings)",
			},
			"public_key_data": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A public key generated for LDAP authentication method on Akeyless [RSA2048] in encoded in base 64 format",
			},
			"unique_identifier": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A unique identifier (ID) value should be configured for LDAP, OAuth2 and SAML authentication method types and is usually a value such as the email, username, or upn for example. Whenever a user logs in with a token, these authentication types issue a sub claim that contains details uniquely identifying that user. This sub claim includes a key containing the ID value that you configured, and is used to distinguish between different users from within the same organization.",
				Default:     "users",
			},
		},
	}
}

func resourceAuthMethodLdapCreate(d *schema.ResourceData, m interface{}) error {
	fmt.Println("--- create ---")

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	accessExpires := d.Get("access_expires").(int)
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	jwtTtl := d.Get("jwt_ttl").(int)
	publicKeyData := d.Get("public_key_data").(string)
	uniqueIdentifier := d.Get("unique_identifier").(string)

	body := akeyless.CreateAuthMethodLDAP{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.PublicKeyData, publicKeyData)
	common.GetAkeylessPtr(&body.UniqueIdentifier, uniqueIdentifier)

	_, _, err := client.CreateAuthMethodLDAP(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodLdapRead(d *schema.ResourceData, m interface{}) error {
	fmt.Println("--- read ---")

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GetAuthMethod{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GetAuthMethod(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}

	if rOut.AccessInfo != nil {
		accessInfo := *rOut.AccessInfo
		if accessInfo.AccessExpires != nil {
			err = d.Set("access_expires", *accessInfo.AccessExpires)
			if err != nil {
				return err
			}
		}
		if accessInfo.ForceSubClaims != nil {
			err = d.Set("force_sub_claims", *accessInfo.ForceSubClaims)
			if err != nil {
				return err
			}
		}
		bodyAcc := akeyless.GetAccountSettings{
			Token: &token,
		}
		rOutAcc, _, err := client.GetAccountSettings(ctx).Body(bodyAcc).Execute()
		if err != nil {
			if errors.As(err, &apiErr) {
				if res.StatusCode == http.StatusNotFound {
					// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
					d.SetId("")
					return nil
				}
				return fmt.Errorf("can't get account settings: %v", string(apiErr.Body()))
			}
			return fmt.Errorf("can't get account settings: %v", err)
		}
		jwtDefault := *rOutAcc.SystemAccessCredsSettings.JwtTtlDefault
		if accessInfo.JwtTtl != nil {
			if *accessInfo.JwtTtl != jwtDefault || d.Get("jwt_ttl").(int) != 0 {
				err = d.Set("jwt_ttl", *accessInfo.JwtTtl)
				if err != nil {
					return err
				}
			}
		}
		if accessInfo.LdapAccessRules.UniqueIdentifier != nil {
			err = d.Set("unique_identifier", *accessInfo.LdapAccessRules.UniqueIdentifier)
			if err != nil {
				return err
			}
		}

		if accessInfo.CidrWhitelist != nil && *accessInfo.CidrWhitelist != "" {
			err = d.Set("bound_ips", strings.Split(*accessInfo.CidrWhitelist, ","))
			if err != nil {
				return err
			}
		}
		if accessInfo.ApiKeyAccessRules != nil {
			err = d.Set("public_key_data", *accessInfo.ApiKeyAccessRules)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceAuthMethodLdapUpdate(d *schema.ResourceData, m interface{}) error {
	fmt.Println("--- update ---")

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	name := d.Get("name").(string)
	accessExpires := d.Get("access_expires").(int)
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	jwtTtl := d.Get("jwt_ttl").(int)
	publicKeyData := d.Get("public_key_data").(string)
	uniqueIdentifier := d.Get("unique_identifier").(string)

	body := akeyless.UpdateAuthMethodLDAP{
		Name:             name,
		UniqueIdentifier: &uniqueIdentifier,
		Token:            &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.PublicKeyData, publicKeyData)

	_, _, err := client.UpdateAuthMethodLDAP(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodLdapDelete(d *schema.ResourceData, m interface{}) error {
	fmt.Println("--- delete ---")

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteAuthMethod{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteAuthMethod(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceAuthMethodLdapImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GetAuthMethod{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GetAuthMethod(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
