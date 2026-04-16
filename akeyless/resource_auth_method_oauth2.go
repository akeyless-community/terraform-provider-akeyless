package akeyless

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAuthMethodOauth2() *schema.Resource {
	return &schema.Resource{
		Description: "AOAuth2 Auth Method Resource",
		Create:      resourceAuthMethodOauth2Create,
		Read:        resourceAuthMethodOauth2Read,
		Update:      resourceAuthMethodOauth2Update,
		Delete:      resourceAuthMethodOauth2Delete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodOauth2Import,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Auth Method name",
				ForceNew:         true,
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"access_expires": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Access expiration date in Unix timestamp (select 0 for access without expiry date)",
				Default:     0,
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
				Description: "if true: enforce role-association must include sub claims",
			},
			"jwt_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Jwt TTL",
				Default:     0,
			},
			"jwks_uri": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.",
			},
			"jwks_json_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server. base64 encoded string",
			},
			"unique_identifier": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A unique identifier (ID) value should be configured for OAuth2, LDAP and SAML authentication method types and is usually a value such as the email, username, or upn for example. Whenever a user logs in with a token, these authentication types issue a sub claim that contains details uniquely identifying that user. This sub claim includes a key containing the ID value that you configured, and is used to distinguish between different users from within the same organization.",
			},
			"bound_client_ids": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "The clients ids that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Issuer URL",
			},
			"audience": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The audience in the JWT",
			},
			"audit_logs_claims": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Subclaims to include in audit logs, e.g \"--audit-logs-claims email --audit-logs-claims username\"",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"gateway_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Akeyless Gateway URL (Configuration Management port). Relevant only when the jwks-uri is accessible only from the gateway.",
			},
			"allowed_client_type": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Limit the auth method usage for specific client types [cli,ui,gateway-admin,sdk,mobile,extension]",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "CertificateFile Path to a file that contain the certificate in a PEM format.",
			},
			"cert_file_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "CertificateFileData PEM Certificate in a Base64 format.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Auth Method description",
			},
			"expiration_event_in": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "How many days before the expiration of the auth method would you like to be notified",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"gw_bound_ips": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A CIDR whitelist with the GW IPs that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"product_type": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Choose the relevant product type for the auth method [sm, sra, pm, dp, ca]",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"subclaims_delimiters": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of additional sub claims delimiters (relevant only for SAML, OIDC, OAuth2/JWT)",
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

func resourceAuthMethodOauth2Create(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	accessExpires := d.Get("access_expires").(int)
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	jwtTtl := d.Get("jwt_ttl").(int)
	jwksUri := d.Get("jwks_uri").(string)
	jwksJsonData := d.Get("jwks_json_data").(string)
	uniqueIdentifier := d.Get("unique_identifier").(string)
	boundClientIdsSet := d.Get("bound_client_ids").(*schema.Set)
	boundClientIds := common.ExpandStringList(boundClientIdsSet.List())
	issuer := d.Get("issuer").(string)
	audience := d.Get("audience").(string)
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	gatewayUrl := d.Get("gateway_url").(string)
	allowedClientTypeSet := d.Get("allowed_client_type").(*schema.Set)
	allowedClientType := common.ExpandStringList(allowedClientTypeSet.List())
	cert := d.Get("cert").(string)
	certFileData := d.Get("cert_file_data").(string)
	description := d.Get("description").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	gwBoundIpsSet := d.Get("gw_bound_ips").(*schema.Set)
	gwBoundIps := common.ExpandStringList(gwBoundIpsSet.List())
	productTypeSet := d.Get("product_type").(*schema.Set)
	productType := common.ExpandStringList(productTypeSet.List())
	subclaimsDelimitersSet := d.Get("subclaims_delimiters").(*schema.Set)
	subclaimsDelimiters := common.ExpandStringList(subclaimsDelimitersSet.List())

	body := akeyless_api.AuthMethodCreateOauth2{
		Name:             name,
		UniqueIdentifier: uniqueIdentifier,
		Token:            &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwksUri, jwksUri)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.BoundClientIds, boundClientIds)
	common.GetAkeylessPtr(&body.Issuer, issuer)
	common.GetAkeylessPtr(&body.Audience, audience)
	common.GetAkeylessPtr(&body.JwksJsonData, jwksJsonData)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.GatewayUrl, gatewayUrl)
	common.GetAkeylessPtr(&body.AllowedClientType, allowedClientType)
	common.GetAkeylessPtr(&body.Cert, cert)
	common.GetAkeylessPtr(&body.CertFileData, certFileData)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ProductType, productType)
	common.GetAkeylessPtr(&body.SubclaimsDelimiters, subclaimsDelimiters)

	rOut, resp, err := client.AuthMethodCreateOauth2(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Auth Method", resp, err)
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

func resourceAuthMethodOauth2Read(d *schema.ResourceData, m interface{}) error {
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
		return common.HandleReadError(d, "can't get value", res, err)
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

	if rOut.AccessInfo.Oauth2AccessRules.JwksUri != nil {
		err = d.Set("jwks_uri", *rOut.AccessInfo.Oauth2AccessRules.JwksUri)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.Oauth2AccessRules.JwksJsonData != nil {
		err = d.Set("jwks_json_data", *rOut.AccessInfo.Oauth2AccessRules.JwksJsonData)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.Oauth2AccessRules.UniqueIdentifier != nil {
		err = d.Set("unique_identifier", *rOut.AccessInfo.Oauth2AccessRules.UniqueIdentifier)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.Oauth2AccessRules.Issuer != nil {
		err = d.Set("issuer", *rOut.AccessInfo.Oauth2AccessRules.Issuer)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.Oauth2AccessRules.Audience != nil {
		err = d.Set("audience", *rOut.AccessInfo.Oauth2AccessRules.Audience)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.Oauth2AccessRules.BoundClientsId != nil {
		err = d.Set("bound_client_ids", rOut.AccessInfo.Oauth2AccessRules.BoundClientsId)
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

	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}

	if d.Get("gateway_url").(string) != "" {
		if rOut.AccessInfo.Oauth2AccessRules.AuthorizedGwClusterName == nil {
			return fmt.Errorf("gateway_url is set, but the auth method does not have an authorized gateway cluster name")
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

	if rOut.Description != nil {
		err = d.Set("description", *rOut.Description)
		if err != nil {
			return err
		}
	}

	if len(rOut.ExpirationEvents) > 0 {
		expirationEventIn := make([]string, 0)
		for _, event := range rOut.ExpirationEvents {
			if event.SecondsBefore != nil {
				days := *event.SecondsBefore / 86400
				expirationEventIn = append(expirationEventIn, strconv.FormatInt(days, 10))
			}
		}
		if len(expirationEventIn) > 0 {
			err = d.Set("expiration_event_in", expirationEventIn)
			if err != nil {
				return err
			}
		}
	}

	if rOut.AccessInfo.GwCidrWhitelist != nil && *rOut.AccessInfo.GwCidrWhitelist != "" {
		err = d.Set("gw_bound_ips", strings.Split(*rOut.AccessInfo.GwCidrWhitelist, ","))
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.ProductTypes != nil {
		err = d.Set("product_type", rOut.AccessInfo.ProductTypes)
		if err != nil {
			return err
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

func resourceAuthMethodOauth2Update(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	accessExpires := d.Get("access_expires").(int)
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	jwtTtl := d.Get("jwt_ttl").(int)
	jwksUri := d.Get("jwks_uri").(string)
	jwksJsonData := d.Get("jwks_json_data").(string)
	uniqueIdentifier := d.Get("unique_identifier").(string)
	boundClientIdsSet := d.Get("bound_client_ids").(*schema.Set)
	boundClientIds := common.ExpandStringList(boundClientIdsSet.List())
	issuer := d.Get("issuer").(string)
	audience := d.Get("audience").(string)
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	gatewayUrl := d.Get("gateway_url").(string)
	allowedClientTypeSet := d.Get("allowed_client_type").(*schema.Set)
	allowedClientType := common.ExpandStringList(allowedClientTypeSet.List())
	cert := d.Get("cert").(string)
	certFileData := d.Get("cert_file_data").(string)
	description := d.Get("description").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	gwBoundIpsSet := d.Get("gw_bound_ips").(*schema.Set)
	gwBoundIps := common.ExpandStringList(gwBoundIpsSet.List())
	productTypeSet := d.Get("product_type").(*schema.Set)
	productType := common.ExpandStringList(productTypeSet.List())
	subclaimsDelimitersSet := d.Get("subclaims_delimiters").(*schema.Set)
	subclaimsDelimiters := common.ExpandStringList(subclaimsDelimitersSet.List())

	body := akeyless_api.AuthMethodUpdateOauth2{
		Name:             name,
		UniqueIdentifier: uniqueIdentifier,
		Token:            &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwksUri, jwksUri)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.BoundClientIds, boundClientIds)
	common.GetAkeylessPtr(&body.Issuer, issuer)
	common.GetAkeylessPtr(&body.Audience, audience)
	common.GetAkeylessPtr(&body.NewName, name)
	common.GetAkeylessPtr(&body.JwksJsonData, jwksJsonData)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.GatewayUrl, gatewayUrl)
	common.GetAkeylessPtr(&body.AllowedClientType, allowedClientType)
	common.GetAkeylessPtr(&body.Cert, cert)
	common.GetAkeylessPtr(&body.CertFileData, certFileData)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ProductType, productType)
	common.GetAkeylessPtr(&body.SubclaimsDelimiters, subclaimsDelimiters)

	_, resp, err := client.AuthMethodUpdateOauth2(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update auth method", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodOauth2Delete(d *schema.ResourceData, m interface{}) error {
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

func resourceAuthMethodOauth2Import(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAuthMethodOauth2Read(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
