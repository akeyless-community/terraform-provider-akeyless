package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
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
				Default:     0,
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
				Optional:    true,
				Description: "Creds expiration time in minutes",
				Default:     0,
			},
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The type of the GCP Auth Method (iam/gce)",
			},
			"audience": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The audience to verify in the JWT received by the client",
				Default:     "akeyless.io",
			},
			"service_account_creds_data": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Service Account creds data, base64 encoded",
			},
			"bound_projects": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "A list of GCP project IDs. Clients must belong to any of the provided projects in order to authenticate. For multiple values repeat this flag.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_service_accounts": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "A list of Service Accounts. Clients must belong to any of the provided service accounts in order to authenticate. For multiple values repeat this flag.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_zones": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "GCE only. A list of zones. GCE instances must belong to any of the provided zones in order to authenticate. For multiple values repeat this flag.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_regions": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "GCE only. A list of regions. GCE instances must belong to any of the provided regions in order to authenticate. For multiple values repeat this flag.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_labels": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "GCE only. A list of GCP labels formatted as key:value pairs that must be set on instances in order to authenticate. For multiple values repeat this flag.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"access_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Auth Method access ID",
			},
			"audit_logs_claims": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Subclaims to include in audit logs",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceAuthMethodGcpCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
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

	body := akeyless_api.CreateAuthMethodGCP{
		Name:     name,
		Type:     gcptype,
		Audience: audience,
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
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

	rOut, _, err := client.CreateAuthMethodGCP(ctx).Body(body).Execute()
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

func resourceAuthMethodGcpRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.GetAuthMethod{
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
		err = d.Set("bound_projects", *rOut.AccessInfo.GcpAccessRules.BoundProjects)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.GcpAccessRules.BoundServiceAccounts != nil {
		err = d.Set("bound_service_accounts", *rOut.AccessInfo.GcpAccessRules.BoundServiceAccounts)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.GcpAccessRules.BoundZones != nil {
		err = d.Set("bound_zones", *rOut.AccessInfo.GcpAccessRules.BoundZones)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.GcpAccessRules.BoundRegions != nil {
		err = d.Set("bound_regions", *rOut.AccessInfo.GcpAccessRules.BoundRegions)
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
		err = d.Set("audit_logs_claims", *rOut.AccessInfo.AuditLogsClaims)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceAuthMethodGcpUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
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

	body := akeyless_api.UpdateAuthMethodGCP{
		Name:     name,
		Type:     gcptype,
		Audience: audience,
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
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

	_, _, err := client.UpdateAuthMethodGCP(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodGcpDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.DeleteAuthMethod{
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
