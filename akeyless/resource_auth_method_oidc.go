package akeyless

import (
	"context"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceAuthMethodOidc() *schema.Resource {
	return &schema.Resource{
		Description: "OIDC Auth Method Resource",
		Create:      resourceAuthMethodOidcCreate,
		Read:        resourceAuthMethodOidcRead,
		Update:      resourceAuthMethodOidcUpdate,
		Delete:      resourceAuthMethodOidcDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodOidcImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("client_secret"), cty.GetAttrPath("client_secret_wo")),
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
			"issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Issuer URL",
			},
			"client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client ID",
			},
			"client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client Secret",
			},
			"client_secret_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"client_secret_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "client_secret (write-only, not stored in state). Requires Terraform 1.11+. Bump client_secret_wo_version to change it.",
			},
			"client_secret_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"client_secret_wo"},
				Description:  "Version trigger for client_secret_wo. Increment to update the value.",
			},
			"unique_identifier": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A unique identifier (ID) value should be configured for OIDC, OAuth2, LDAP and SAML authentication method types and is usually a value such as the email, username, or upn for example. Whenever a user logs in with a token, these authentication types issue a sub claim that contains details uniquely identifying that user. This sub claim includes a key containing the ID value that you configured, and is used to distinguish between different users from within the same organization.",
			},
			"allowed_redirect_uri": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Allowed redirect URIs after the authentication",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"required_scopes": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "RequiredScopes is a list of required scopes that the oidc method will request from the oidc provider and the user must approve",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"required_scopes_prefix": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "RequiredScopesPrefix is a a prefix to add to all required-scopes when requesting them from the oidc server (for example, azures' Application ID URI)",
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
			"allowed_client_type": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "limit the auth method usage for specific client types [cli,ui,gateway-admin,sdk,mobile,extension]",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"audience": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Audience claim to be used as part of the authentication flow. In case set, it must match the one configured on the Identity Provider's Application",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Auth Method description",
			},
			"expiration_event_in": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "How many days before the expiration of the auth method would you like to be notified.",
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

func resourceAuthMethodOidcCreate(d *schema.ResourceData, m interface{}) error {
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
	issuer := d.Get("issuer").(string)
	clientId := d.Get("client_id").(string)
	clientSecret, err := common.EffectiveSecretValue(d, "client_secret", "client_secret_wo")
	if err != nil {
		return err
	}
	uniqueIdentifier := d.Get("unique_identifier").(string)
	allowedRedirectUriSet := d.Get("allowed_redirect_uri").(*schema.Set)
	allowedRedirectUri := common.ExpandStringList(allowedRedirectUriSet.List())
	requiredScopesSet := d.Get("required_scopes").(*schema.Set)
	requiredScopes := common.ExpandStringList(requiredScopesSet.List())
	requiredScopesPrefix := d.Get("required_scopes_prefix").(string)
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	allowedClientTypeSet := d.Get("allowed_client_type").(*schema.Set)
	allowedClientType := common.ExpandStringList(allowedClientTypeSet.List())
	audience := d.Get("audience").(string)
	description := d.Get("description").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	gwBoundIpsSet := d.Get("gw_bound_ips").(*schema.Set)
	gwBoundIps := common.ExpandStringList(gwBoundIpsSet.List())
	productTypeSet := d.Get("product_type").(*schema.Set)
	productType := common.ExpandStringList(productTypeSet.List())
	subclaimsDelimitersSet := d.Get("subclaims_delimiters").(*schema.Set)
	subclaimsDelimiters := common.ExpandStringList(subclaimsDelimitersSet.List())

	body := akeyless_api.AuthMethodCreateOIDC{
		Name:             name,
		UniqueIdentifier: uniqueIdentifier,
		Token:            &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.Issuer, issuer)
	common.GetAkeylessPtr(&body.ClientId, clientId)
	common.GetAkeylessPtr(&body.ClientSecret, clientSecret)
	common.GetAkeylessPtr(&body.AllowedRedirectUri, allowedRedirectUri)
	common.GetAkeylessPtr(&body.RequiredScopes, requiredScopes)
	common.GetAkeylessPtr(&body.RequiredScopesPrefix, requiredScopesPrefix)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.AllowedClientType, allowedClientType)
	common.GetAkeylessPtr(&body.Audience, audience)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ProductType, productType)
	common.GetAkeylessPtr(&body.SubclaimsDelimiters, subclaimsDelimiters)

	rOut, resp, err := client.AuthMethodCreateOIDC(ctx).Body(body).Execute()
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

func resourceAuthMethodOidcRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.AccessInfo.OidcAccessRules.Issuer != nil {
		err = d.Set("issuer", *rOut.AccessInfo.OidcAccessRules.Issuer)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.OidcAccessRules.ClientId != nil {
		err = d.Set("client_id", *rOut.AccessInfo.OidcAccessRules.ClientId)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.OidcAccessRules.ClientSecret != nil {
		err = common.SetSecretFromRead(d, "client_secret", "client_secret_wo", "client_secret_wo_version", *rOut.AccessInfo.OidcAccessRules.ClientSecret)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.OidcAccessRules.UniqueIdentifier != nil {
		err = d.Set("unique_identifier", *rOut.AccessInfo.OidcAccessRules.UniqueIdentifier)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.OidcAccessRules.AllowedRedirectURIs != nil {
		err = d.Set("allowed_redirect_uri", rOut.AccessInfo.OidcAccessRules.AllowedRedirectURIs)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.OidcAccessRules.RequiredScopes != nil {
		err = d.Set("required_scopes", rOut.AccessInfo.OidcAccessRules.RequiredScopes)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.OidcAccessRules.RequiredScopesPrefix != nil {
		err = d.Set("required_scopes_prefix", *rOut.AccessInfo.OidcAccessRules.RequiredScopesPrefix)
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

	if len(rOut.AccessInfo.AllowedClientType) > 0 {
		// Only set allowed_client_type if it was explicitly configured by the user
		if _, ok := d.GetOk("allowed_client_type"); ok {
			err = d.Set("allowed_client_type", rOut.AccessInfo.AllowedClientType)
			if err != nil {
				return err
			}
		}
	}

	if rOut.AccessInfo.OidcAccessRules.Audience != nil {
		err = d.Set("audience", *rOut.AccessInfo.OidcAccessRules.Audience)
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

func resourceAuthMethodOidcUpdate(d *schema.ResourceData, m interface{}) error {
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
	issuer := d.Get("issuer").(string)
	clientId := d.Get("client_id").(string)
	clientSecret, err := common.SecretValueForUpdate(d, "client_secret", "client_secret_wo")
	if err != nil {
		return err
	}
	uniqueIdentifier := d.Get("unique_identifier").(string)
	allowedRedirectUriSet := d.Get("allowed_redirect_uri").(*schema.Set)
	allowedRedirectUri := common.ExpandStringList(allowedRedirectUriSet.List())
	requiredScopesSet := d.Get("required_scopes").(*schema.Set)
	requiredScopes := common.ExpandStringList(requiredScopesSet.List())
	requiredScopesPrefix := d.Get("required_scopes_prefix").(string)
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	allowedClientTypeSet := d.Get("allowed_client_type").(*schema.Set)
	allowedClientType := common.ExpandStringList(allowedClientTypeSet.List())
	audience := d.Get("audience").(string)
	description := d.Get("description").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	gwBoundIpsSet := d.Get("gw_bound_ips").(*schema.Set)
	gwBoundIps := common.ExpandStringList(gwBoundIpsSet.List())
	productTypeSet := d.Get("product_type").(*schema.Set)
	productType := common.ExpandStringList(productTypeSet.List())
	subclaimsDelimitersSet := d.Get("subclaims_delimiters").(*schema.Set)
	subclaimsDelimiters := common.ExpandStringList(subclaimsDelimitersSet.List())

	body := akeyless_api.AuthMethodUpdateOIDC{
		Name:             name,
		UniqueIdentifier: uniqueIdentifier,
		Token:            &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.Issuer, issuer)
	common.GetAkeylessPtr(&body.ClientId, clientId)
	common.SetOptionalString(&body.ClientSecret, clientSecret)
	common.GetAkeylessPtr(&body.AllowedRedirectUri, allowedRedirectUri)
	common.GetAkeylessPtr(&body.RequiredScopes, requiredScopes)
	common.GetAkeylessPtr(&body.RequiredScopesPrefix, requiredScopesPrefix)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.NewName, name)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.AllowedClientType, allowedClientType)
	common.GetAkeylessPtr(&body.Audience, audience)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ProductType, productType)
	common.GetAkeylessPtr(&body.SubclaimsDelimiters, subclaimsDelimiters)

	_, resp, err := client.AuthMethodUpdateOIDC(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update auth method", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodOidcDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceAuthMethodOidcImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAuthMethodOidcRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
