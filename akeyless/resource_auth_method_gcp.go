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

func resourceAuthMethodGcp() *schema.Resource {
	return &schema.Resource{
		Description: "GCE Auth Method Resource",
		Create:      resourceAuthMethodGcpCreate,
		Read:        resourceAuthMethodGcpRead,
		Update:      resourceAuthMethodGcpUpdate,
		Delete:      resourceAuthMethodGcpDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodGcpImport,
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
			"allowed_client_type": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "limit the auth method usage for specific client types [cli,ui,gateway-admin,sdk,mobile,extension]",
				Elem:        &schema.Schema{Type: schema.TypeString},
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
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Type of the GCP Access Rules",
			},
			"audience": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The audience to verify in the JWT received by the client",
				Default:     "akeyless.io",
			},
			"service_account_creds_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ServiceAccount credentials data instead of giving a file path, base64 encoded",
			},
			"bound_projects": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "=== Human and Machine authentication section === Array of GCP project IDs. Only entities belonging to any of the provided projects can authenticate.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_service_accounts": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of service accounts the service account must be part of in order to be authenticated.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_zones": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "=== Machine authentication section === List of zones that a GCE instance must belong to in order to be authenticated. TODO: If bound_instance_groups is provided, it is assumed to be a zonal group and the group must belong to this zone.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_regions": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of regions that a GCE instance must belong to in order to be authenticated. TODO: If bound_instance_groups is provided, it is assumed to be a regional group and the group must belong to this region. If bound_zones are provided, this attribute is ignored.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_labels": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A comma-separated list of GCP labels formatted as \"key:value\" strings that must be set on authorized GCE instances. TODO: Because GCP labels are not currently ACL'd ....",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"audit_logs_claims": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Subclaims to include in audit logs, e.g \"--audit-logs-claims email --audit-logs-claims username\"",
				Elem:        &schema.Schema{Type: schema.TypeString},
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
			"unique_identifier": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A unique identifier (ID) value which is a \"sub claim\" name that contains details uniquely identifying that resource. This \"sub claim\" is used to distinguish between different identities.",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
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

func resourceAuthMethodGcpCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	accessExpires := d.Get("access_expires").(int)
	allowedClientTypeSet := d.Get("allowed_client_type").(*schema.Set)
	allowedClientType := common.ExpandStringList(allowedClientTypeSet.List())
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	jwtTtl := d.Get("jwt_ttl").(int)
	gcptype := d.Get("type").(string)
	audience := d.Get("audience").(string)
	serviceAccountCredsData := d.Get("service_account_creds_data").(string)
	boundProjectsSet := d.Get("bound_projects").(*schema.Set)
	boundProjects := common.ExpandStringList(boundProjectsSet.List())
	boundServiceAccountsSet := d.Get("bound_service_accounts").(*schema.Set)
	boundServiceAccounts := common.ExpandStringList(boundServiceAccountsSet.List())
	boundZonesSet := d.Get("bound_zones").(*schema.Set)
	boundZones := common.ExpandStringList(boundZonesSet.List())
	boundRegionsSet := d.Get("bound_regions").(*schema.Set)
	boundRegions := common.ExpandStringList(boundRegionsSet.List())
	boundLabelsSet := d.Get("bound_labels").(*schema.Set)
	boundLabels := common.ExpandStringList(boundLabelsSet.List())
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	description := d.Get("description").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	gwBoundIpsSet := d.Get("gw_bound_ips").(*schema.Set)
	gwBoundIps := common.ExpandStringList(gwBoundIpsSet.List())
	productTypeSet := d.Get("product_type").(*schema.Set)
	productType := common.ExpandStringList(productTypeSet.List())
	uniqueIdentifier := d.Get("unique_identifier").(string)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.AuthMethodCreateGcp{
		Name:     name,
		Type:     gcptype,
		Audience: audience,
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.AllowedClientType, allowedClientType)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.ServiceAccountCredsData, serviceAccountCredsData)
	common.GetAkeylessPtr(&body.BoundProjects, boundProjects)
	common.GetAkeylessPtr(&body.BoundServiceAccounts, boundServiceAccounts)
	common.GetAkeylessPtr(&body.BoundZones, boundZones)
	common.GetAkeylessPtr(&body.BoundRegions, boundRegions)
	common.GetAkeylessPtr(&body.BoundLabels, boundLabels)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ProductType, productType)
	common.GetAkeylessPtr(&body.UniqueIdentifier, uniqueIdentifier)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	rOut, resp, err := client.AuthMethodCreateGcp(ctx).Body(body).Execute()
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

func resourceAuthMethodGcpRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.AccessInfo.AllowedClientType != nil && len(rOut.AccessInfo.AllowedClientType) > 0 {
		// Only set allowed_client_type if it was explicitly configured by the user
		if _, ok := d.GetOk("allowed_client_type"); ok {
			err = d.Set("allowed_client_type", rOut.AccessInfo.AllowedClientType)
			if err != nil {
				return err
			}
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

	if rOut.AccessInfo.GcpAccessRules.Type != nil {
		err = d.Set("type", *rOut.AccessInfo.GcpAccessRules.Type)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.GcpAccessRules.Audience != nil {
		err = d.Set("audience", *rOut.AccessInfo.GcpAccessRules.Audience)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.GcpAccessRules.BoundProjects != nil {
		err = d.Set("bound_projects", rOut.AccessInfo.GcpAccessRules.BoundProjects)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.GcpAccessRules.BoundServiceAccounts != nil {
		err = d.Set("bound_service_accounts", rOut.AccessInfo.GcpAccessRules.BoundServiceAccounts)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.GcpAccessRules.BoundZones != nil {
		err = d.Set("bound_zones", rOut.AccessInfo.GcpAccessRules.BoundZones)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.GcpAccessRules.BoundRegions != nil {
		err = d.Set("bound_regions", rOut.AccessInfo.GcpAccessRules.BoundRegions)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.GcpAccessRules.BoundLabels != nil {
		boundLabels := *rOut.AccessInfo.GcpAccessRules.BoundLabels
		a := make([]string, 0)
		if len(boundLabels) != 0 {
			for k, v := range boundLabels {
				a = append(a, fmt.Sprintf("%s:%s", k, v))
			}
		}

		err = d.Set("bound_labels", a)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.GcpAccessRules.ServiceAccount != nil {
		err = d.Set("service_account_creds_data", *rOut.AccessInfo.GcpAccessRules.ServiceAccount)
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

	if rOut.Description != nil {
		err = d.Set("description", *rOut.Description)
		if err != nil {
			return err
		}
	}

	if rOut.ExpirationEvents != nil {
		expirationEventIn := make([]string, 0)
		for _, event := range rOut.ExpirationEvents {
			if event.SecondsBefore != nil {
				// Convert seconds to days (86400 seconds = 1 day)
				days := int(*event.SecondsBefore) / 86400
				expirationEventIn = append(expirationEventIn, strconv.Itoa(days))
			}
		}
		err = d.Set("expiration_event_in", expirationEventIn)
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

	if rOut.AccessInfo.GcpAccessRules.UniqueIdentifier != nil {
		err = d.Set("unique_identifier", *rOut.AccessInfo.GcpAccessRules.UniqueIdentifier)
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

	d.SetId(path)

	return nil
}

func resourceAuthMethodGcpUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	accessExpires := d.Get("access_expires").(int)
	allowedClientTypeSet := d.Get("allowed_client_type").(*schema.Set)
	allowedClientType := common.ExpandStringList(allowedClientTypeSet.List())
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	jwtTtl := d.Get("jwt_ttl").(int)
	gcptype := d.Get("type").(string)
	audience := d.Get("audience").(string)
	serviceAccountCredsData := d.Get("service_account_creds_data").(string)
	boundProjectsSet := d.Get("bound_projects").(*schema.Set)
	boundProjects := common.ExpandStringList(boundProjectsSet.List())
	boundServiceAccountsSet := d.Get("bound_service_accounts").(*schema.Set)
	boundServiceAccounts := common.ExpandStringList(boundServiceAccountsSet.List())
	boundZonesSet := d.Get("bound_zones").(*schema.Set)
	boundZones := common.ExpandStringList(boundZonesSet.List())
	boundRegionsSet := d.Get("bound_regions").(*schema.Set)
	boundRegions := common.ExpandStringList(boundRegionsSet.List())
	boundLabelsSet := d.Get("bound_labels").(*schema.Set)
	boundLabels := common.ExpandStringList(boundLabelsSet.List())
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	description := d.Get("description").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	gwBoundIpsSet := d.Get("gw_bound_ips").(*schema.Set)
	gwBoundIps := common.ExpandStringList(gwBoundIpsSet.List())
	productTypeSet := d.Get("product_type").(*schema.Set)
	productType := common.ExpandStringList(productTypeSet.List())
	uniqueIdentifier := d.Get("unique_identifier").(string)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.AuthMethodUpdateGcp{
		Name:     name,
		Type:     gcptype,
		Audience: audience,
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.AllowedClientType, allowedClientType)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.ServiceAccountCredsData, serviceAccountCredsData)
	common.GetAkeylessPtr(&body.BoundProjects, boundProjects)
	common.GetAkeylessPtr(&body.BoundServiceAccounts, boundServiceAccounts)
	common.GetAkeylessPtr(&body.BoundZones, boundZones)
	common.GetAkeylessPtr(&body.BoundRegions, boundRegions)
	common.GetAkeylessPtr(&body.BoundLabels, boundLabels)
	common.GetAkeylessPtr(&body.NewName, name)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ProductType, productType)
	common.GetAkeylessPtr(&body.UniqueIdentifier, uniqueIdentifier)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, resp, err := client.AuthMethodUpdateGcp(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update auth method", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodGcpDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceAuthMethodGcpImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAuthMethodGcpRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
