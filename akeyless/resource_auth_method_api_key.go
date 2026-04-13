package akeyless

import (
	"context"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAuthMethodApiKey() *schema.Resource {
	return &schema.Resource{
		Description: "API Key Auth Method Resource",
		Create:      resourceAuthMethodApiKeyCreate,
		Read:        resourceAuthMethodApiKeyRead,
		Update:      resourceAuthMethodApiKeyUpdate,
		Delete:      resourceAuthMethodApiKeyDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodApiKeyImport,
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
			"access_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Auth Method access ID",
			},
			"access_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Auth Method access key",
				Sensitive:   true,
			},
		},
	}
}

func resourceAuthMethodApiKeyCreate(d *schema.ResourceData, m interface{}) error {
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
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	allowedClientTypeSet := d.Get("allowed_client_type").(*schema.Set)
	allowedClientType := common.ExpandStringList(allowedClientTypeSet.List())
	description := d.Get("description").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	gwBoundIpsSet := d.Get("gw_bound_ips").(*schema.Set)
	gwBoundIps := common.ExpandStringList(gwBoundIpsSet.List())
	productTypeSet := d.Get("product_type").(*schema.Set)
	productType := common.ExpandStringList(productTypeSet.List())

	body := akeyless_api.AuthMethodCreateApiKey{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.AllowedClientType, allowedClientType)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ProductType, productType)

	rOut, resp, err := client.AuthMethodCreateApiKey(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create auth method", resp, err)
	}

	if rOut.AccessId != nil {
		err = d.Set("access_id", *rOut.AccessId)
		if err != nil {
			return err
		}
	}
	if rOut.AccessKey != nil {
		err = d.Set("access_key", rOut.AccessKey)
		if err != nil {
			return err
		}
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodApiKeyRead(d *schema.ResourceData, m interface{}) error {
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
		return common.HandleReadError(d, "failed to get value", res, err)
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

	d.SetId(path)

	return nil
}

func resourceAuthMethodApiKeyUpdate(d *schema.ResourceData, m interface{}) error {
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
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	allowedClientTypeSet := d.Get("allowed_client_type").(*schema.Set)
	allowedClientType := common.ExpandStringList(allowedClientTypeSet.List())
	description := d.Get("description").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	gwBoundIpsSet := d.Get("gw_bound_ips").(*schema.Set)
	gwBoundIps := common.ExpandStringList(gwBoundIpsSet.List())
	productTypeSet := d.Get("product_type").(*schema.Set)
	productType := common.ExpandStringList(productTypeSet.List())

	body := akeyless_api.AuthMethodUpdateApiKey{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.NewName, name)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.AllowedClientType, allowedClientType)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ProductType, productType)

	_, resp, err := client.AuthMethodUpdateApiKey(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update auth method", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodApiKeyDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceAuthMethodApiKeyImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAuthMethodApiKeyRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
