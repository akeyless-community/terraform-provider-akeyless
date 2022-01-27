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

func resourceAuthMethodUniversalIdentity() *schema.Resource {
	return &schema.Resource{
		Description: "Akeyless Universal Identity Auth Method Resource",
		Create:      resourceAuthMethodUniversalIdentityCreate,
		Read:        resourceAuthMethodUniversalIdentityRead,
		Update:      resourceAuthMethodUniversalIdentityUpdate,
		Delete:      resourceAuthMethodUniversalIdentityDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodUniversalIdentityImport,
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
			"deny_rotate": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Deny from the token to rotate",
			},
			"deny_inheritance": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Deny from root to create children",
			},
			"ttl": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Token ttl (in minutes)",
				Default:     60,
			},
			"access_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Auth Method access ID",
			},
		},
	}
}

func resourceAuthMethodUniversalIdentityCreate(d *schema.ResourceData, m interface{}) error {
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
	denyRotate := d.Get("deny_rotate").(bool)
	denyInheritance := d.Get("deny_inheritance").(bool)
	ttl := d.Get("ttl").(int)

	body := akeyless.CreateAuthMethodUniversalIdentity{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.DenyRotate, denyRotate)
	common.GetAkeylessPtr(&body.DenyInheritance, denyInheritance)
	common.GetAkeylessPtr(&body.Ttl, ttl)

	rOut, _, err := client.CreateAuthMethodUniversalIdentity(ctx).Body(body).Execute()
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

func resourceAuthMethodUniversalIdentityRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.AccessInfo.UniversalIdentityAccessRules.DenyRotate != nil {
		err = d.Set("deny_rotate", *rOut.AccessInfo.UniversalIdentityAccessRules.DenyRotate)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.UniversalIdentityAccessRules.DenyInheritance != nil {
		err = d.Set("deny_inheritance", *rOut.AccessInfo.UniversalIdentityAccessRules.DenyInheritance)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.UniversalIdentityAccessRules.Ttl != nil {
		err = d.Set("ttl", *rOut.AccessInfo.UniversalIdentityAccessRules.Ttl)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceAuthMethodUniversalIdentityUpdate(d *schema.ResourceData, m interface{}) error {
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
	denyRotate := d.Get("deny_rotate").(bool)
	denyInheritance := d.Get("deny_inheritance").(bool)
	ttl := d.Get("ttl").(int)

	body := akeyless.UpdateAuthMethodUniversalIdentity{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.DenyRotate, denyRotate)
	common.GetAkeylessPtr(&body.DenyInheritance, denyInheritance)
	common.GetAkeylessPtr(&body.Ttl, ttl)
	common.GetAkeylessPtr(&body.NewName, name)

	_, _, err := client.UpdateAuthMethodUniversalIdentity(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodUniversalIdentityDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceAuthMethodUniversalIdentityImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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
