package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAuthMethodSaml() *schema.Resource {
	return &schema.Resource{
		Description: "SAML Auth Method Resource",
		Create:      resourceAuthMethodSamlCreate,
		Read:        resourceAuthMethodSamlRead,
		Update:      resourceAuthMethodSamlUpdate,
		Delete:      resourceAuthMethodSamlDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodSamlImport,
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
				Optional:    true,
				Description: "Access expiration date in Unix timestamp (select 0 for access without expiry date)",
				Default:     "0",
			},
			"bound_ips": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A CIDR whitelist with the IPs that the access is restricted to",
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
				Description: "Creds expiration time in minutes",
				Default:     0,
			},
			"unique_identifier": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A unique identifier (ID) value should be configured for OAuth2, LDAP and SAML authentication method types and is usually a value such as the email, username, or upn for example. Whenever a user logs in with a token, these authentication types issue a sub claim that contains details uniquely identifying that user. This sub claim includes a key containing the ID value that you configured, and is used to distinguish between different users from within the same organization.",
			},
			"idp_metadata_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "IDP metadata url",
			},
			"idp_metadata_xml_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "IDP metadata xml data for saml authentication",
			},
			"allowed_redirect_uri": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Allowed redirect URIs after the authentication (default is https://console.akeyless.io/login-saml to enable SAML via Akeyless Console and  http://127.0.0.1:* to enable SAML via akeyless CLI)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"audit_logs_claims": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Subclaims to include in audit logs",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this auth method, [true/false]",
				Default:     "false",
			},
			"access_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Auth Method access ID",
			},
		},
	}
}

func resourceAuthMethodSamlCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	accessExpires := d.Get("access_expires").(int)
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	jwtTtl := d.Get("jwt_ttl").(int)
	uniqueIdentifier := d.Get("unique_identifier").(string)
	idpMetadataUrl := d.Get("idp_metadata_url").(string)
	idpMetadataXmlData := d.Get("idp_metadata_xml_data").(string)
	allowedRedirectUriSet := d.Get("allowed_redirect_uri").(*schema.Set)
	allowedRedirectUri := common.ExpandStringList(allowedRedirectUriSet.List())
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.AuthMethodCreateSAML{
		Name:             name,
		UniqueIdentifier: uniqueIdentifier,
		Token:            &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.IdpMetadataUrl, idpMetadataUrl)
	common.GetAkeylessPtr(&body.IdpMetadataXmlData, idpMetadataXmlData)
	common.GetAkeylessPtr(&body.AllowedRedirectUri, allowedRedirectUri)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	rOut, _, err := client.AuthMethodCreateSAML(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
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

func resourceAuthMethodSamlRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.AuthMethodGet{
		Name:  path,
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
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
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

	if rOut.AccessInfo.SamlAccessRules.UniqueIdentifier != nil {
		err = d.Set("unique_identifier", *rOut.AccessInfo.SamlAccessRules.UniqueIdentifier)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.SamlAccessRules.IdpMetadataUrl != nil {
		err = d.Set("idp_metadata_url", *rOut.AccessInfo.SamlAccessRules.IdpMetadataUrl)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.SamlAccessRules.IdpMetadataXml != nil {
		err = d.Set("idp_metadata_xml_data", *rOut.AccessInfo.SamlAccessRules.IdpMetadataXml)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.SamlAccessRules.AllowedRedirectURIs != nil {
		err = d.Set("allowed_redirect_uri", *rOut.AccessInfo.SamlAccessRules.AllowedRedirectURIs)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AuditLogsClaims != nil {
		err = d.Set("audit_logs_claims", *rOut.AccessInfo.AuditLogsClaims)
		if err != nil {
			return err
		}
	}

	if rOut.DeleteProtection != nil {
		err = d.Set("delete_protection", strconv.FormatBool(*rOut.DeleteProtection))
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceAuthMethodSamlUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	accessExpires := d.Get("access_expires").(int)
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	jwtTtl := d.Get("jwt_ttl").(int)
	uniqueIdentifier := d.Get("unique_identifier").(string)
	idpMetadataUrl := d.Get("idp_metadata_url").(string)
	idpMetadataXmlData := d.Get("idp_metadata_xml_data").(string)
	allowedRedirectUriSet := d.Get("allowed_redirect_uri").(*schema.Set)
	allowedRedirectUri := common.ExpandStringList(allowedRedirectUriSet.List())
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.AuthMethodUpdateSAML{
		Name:             name,
		UniqueIdentifier: uniqueIdentifier,
		Token:            &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.IdpMetadataUrl, idpMetadataUrl)
	common.GetAkeylessPtr(&body.IdpMetadataXmlData, idpMetadataXmlData)
	common.GetAkeylessPtr(&body.AllowedRedirectUri, allowedRedirectUri)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.NewName, name)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.AuthMethodUpdateSAML(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodSamlDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceAuthMethodSamlImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAuthMethodSamlRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
