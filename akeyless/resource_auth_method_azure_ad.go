package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAuthMethodAzureAd() *schema.Resource {
	return &schema.Resource{
		Description: "Azure Active Directory Auth Method Resource",
		Create:      resourceAuthMethodAzureAdCreate,
		Read:        resourceAuthMethodAzureAdRead,
		Update:      resourceAuthMethodAzureAdUpdate,
		Delete:      resourceAuthMethodAzureAdDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodAzureAdImport,
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
			"bound_tenant_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Azure tenant id that the access is restricted to",
			},
			"issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Issuer URL",
				Default:     "https://sts.windows.net/my-tenant-id/",
			},
			"jwks_uri": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.",
				Default:     "https://login.microsoftonline.com/common/discovery/keys",
			},
			"audience": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The audience in the JWT",
				Default:     "https://management.azure.com/",
			},
			"bound_spid": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of service principal IDs that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_group_id": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of group ids that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_sub_id": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of subscription ids that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_rg_id": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of resource groups that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_providers": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_resource_types": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_resource_names": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc).",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_resource_id": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of full resource ids that the access is restricted to",
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

func resourceAuthMethodAzureAdCreate(d *schema.ResourceData, m interface{}) error {
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
	boundTenantId := d.Get("bound_tenant_id").(string)
	issuer := d.Get("issuer").(string)
	jwksUri := d.Get("jwks_uri").(string)
	audience := d.Get("audience").(string)
	boundSpidSet := d.Get("bound_spid").(*schema.Set)
	boundSpid := common.ExpandStringList(boundSpidSet.List())
	boundGroupIdSet := d.Get("bound_group_id").(*schema.Set)
	boundGroupId := common.ExpandStringList(boundGroupIdSet.List())
	boundSubIdSet := d.Get("bound_sub_id").(*schema.Set)
	boundSubId := common.ExpandStringList(boundSubIdSet.List())
	boundRgIdSet := d.Get("bound_rg_id").(*schema.Set)
	boundRgId := common.ExpandStringList(boundRgIdSet.List())
	boundProvidersSet := d.Get("bound_providers").(*schema.Set)
	boundProviders := common.ExpandStringList(boundProvidersSet.List())
	boundResourceTypesSet := d.Get("bound_resource_types").(*schema.Set)
	boundResourceTypes := common.ExpandStringList(boundResourceTypesSet.List())
	boundResourceNamesSet := d.Get("bound_resource_names").(*schema.Set)
	boundResourceNames := common.ExpandStringList(boundResourceNamesSet.List())
	boundResourceIdSet := d.Get("bound_resource_id").(*schema.Set)
	boundResourceId := common.ExpandStringList(boundResourceIdSet.List())
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.AuthMethodCreateAzureAD{
		Name:          name,
		BoundTenantId: boundTenantId,
		Token:         &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.Issuer, issuer)
	common.GetAkeylessPtr(&body.JwksUri, jwksUri)
	common.GetAkeylessPtr(&body.Audience, audience)
	common.GetAkeylessPtr(&body.BoundSpid, boundSpid)
	common.GetAkeylessPtr(&body.BoundGroupId, boundGroupId)
	common.GetAkeylessPtr(&body.BoundSubId, boundSubId)
	common.GetAkeylessPtr(&body.BoundRgId, boundRgId)
	common.GetAkeylessPtr(&body.BoundProviders, boundProviders)
	common.GetAkeylessPtr(&body.BoundResourceTypes, boundResourceTypes)
	common.GetAkeylessPtr(&body.BoundResourceNames, boundResourceNames)
	common.GetAkeylessPtr(&body.BoundResourceId, boundResourceId)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	rOut, _, err := client.AuthMethodCreateAzureAD(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Auth Method: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Auth Method: %v", err)
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

func resourceAuthMethodAzureAdRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.AccessInfo.AzureAdAccessRules.BoundTenantId != nil {
		err = d.Set("bound_tenant_id", *rOut.AccessInfo.AzureAdAccessRules.BoundTenantId)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.AzureAdAccessRules.Issuer != nil {
		err = d.Set("issuer", *rOut.AccessInfo.AzureAdAccessRules.Issuer)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AzureAdAccessRules.JwksUri != nil {
		err = d.Set("jwks_uri", *rOut.AccessInfo.AzureAdAccessRules.JwksUri)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AzureAdAccessRules.AdEndpoint != nil {
		err = d.Set("audience", *rOut.AccessInfo.AzureAdAccessRules.AdEndpoint)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AzureAdAccessRules.BoundResourceTypes != nil {
		err = d.Set("bound_resource_types", *rOut.AccessInfo.AzureAdAccessRules.BoundResourceTypes)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AzureAdAccessRules.BoundResourceNames != nil {
		err = d.Set("bound_resource_names", *rOut.AccessInfo.AzureAdAccessRules.BoundResourceNames)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.AzureAdAccessRules.BoundServicePrincipalIds != nil {
		err = d.Set("bound_spid", *rOut.AccessInfo.AzureAdAccessRules.BoundServicePrincipalIds)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AzureAdAccessRules.BoundGroupIds != nil {
		err = d.Set("bound_group_id", *rOut.AccessInfo.AzureAdAccessRules.BoundGroupIds)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AzureAdAccessRules.BoundSubscriptionIds != nil {
		err = d.Set("bound_sub_id", *rOut.AccessInfo.AzureAdAccessRules.BoundSubscriptionIds)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AzureAdAccessRules.BoundResourceGroups != nil {
		err = d.Set("bound_rg_id", *rOut.AccessInfo.AzureAdAccessRules.BoundResourceGroups)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AzureAdAccessRules.BoundResourceProviders != nil {
		err = d.Set("bound_providers", *rOut.AccessInfo.AzureAdAccessRules.BoundResourceProviders)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AzureAdAccessRules.BoundResourceIds != nil {
		err = d.Set("bound_resource_id", *rOut.AccessInfo.AzureAdAccessRules.BoundResourceIds)
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

func resourceAuthMethodAzureAdUpdate(d *schema.ResourceData, m interface{}) error {
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
	boundTenantId := d.Get("bound_tenant_id").(string)
	issuer := d.Get("issuer").(string)
	jwksUri := d.Get("jwks_uri").(string)
	audience := d.Get("audience").(string)
	boundSpidSet := d.Get("bound_spid").(*schema.Set)
	boundSpid := common.ExpandStringList(boundSpidSet.List())
	boundGroupIdSet := d.Get("bound_group_id").(*schema.Set)
	boundGroupId := common.ExpandStringList(boundGroupIdSet.List())
	boundSubIdSet := d.Get("bound_sub_id").(*schema.Set)
	boundSubId := common.ExpandStringList(boundSubIdSet.List())
	boundRgIdSet := d.Get("bound_rg_id").(*schema.Set)
	boundRgId := common.ExpandStringList(boundRgIdSet.List())
	boundProvidersSet := d.Get("bound_providers").(*schema.Set)
	boundProviders := common.ExpandStringList(boundProvidersSet.List())
	boundResourceTypesSet := d.Get("bound_resource_types").(*schema.Set)
	boundResourceTypes := common.ExpandStringList(boundResourceTypesSet.List())
	boundResourceNamesSet := d.Get("bound_resource_names").(*schema.Set)
	boundResourceNames := common.ExpandStringList(boundResourceNamesSet.List())
	boundResourceIdSet := d.Get("bound_resource_id").(*schema.Set)
	boundResourceId := common.ExpandStringList(boundResourceIdSet.List())
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.AuthMethodUpdateAzureAD{
		Name:          name,
		BoundTenantId: boundTenantId,
		Token:         &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.Issuer, issuer)
	common.GetAkeylessPtr(&body.JwksUri, jwksUri)
	common.GetAkeylessPtr(&body.Audience, audience)
	common.GetAkeylessPtr(&body.BoundSpid, boundSpid)
	common.GetAkeylessPtr(&body.BoundGroupId, boundGroupId)
	common.GetAkeylessPtr(&body.BoundSubId, boundSubId)
	common.GetAkeylessPtr(&body.BoundRgId, boundRgId)
	common.GetAkeylessPtr(&body.BoundProviders, boundProviders)
	common.GetAkeylessPtr(&body.BoundResourceTypes, boundResourceTypes)
	common.GetAkeylessPtr(&body.BoundResourceNames, boundResourceNames)
	common.GetAkeylessPtr(&body.BoundResourceId, boundResourceId)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.NewName, name)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.AuthMethodUpdateAzureAD(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodAzureAdDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceAuthMethodAzureAdImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAuthMethodAzureAdRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
