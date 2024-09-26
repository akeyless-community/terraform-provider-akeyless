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

func resourceAuthMethodAwsIam() *schema.Resource {
	return &schema.Resource{
		Description: "AWS IAM Auth Method Resource",
		Create:      resourceAuthMethodAwsIamCreate,
		Read:        resourceAuthMethodAwsIamRead,
		Update:      resourceAuthMethodAwsIamUpdate,
		Delete:      resourceAuthMethodAwsIamDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodAwsIamImport,
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
			"bound_aws_account_id": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "A list of AWS account-IDs that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"sts_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: " sts URL",
				Default:     "https://sts.amazonaws.com",
			},
			"bound_arn": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of full arns that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_role_name": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of full role-name that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_role_id": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of full role ids that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_resource_id": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of full resource ids that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_user_name": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of full user-name that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_user_id": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of full user ids that the access is restricted to",
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

func resourceAuthMethodAwsIamCreate(d *schema.ResourceData, m interface{}) error {
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
	boundAwsAccountIdSet := d.Get("bound_aws_account_id").(*schema.Set)
	boundAwsAccountId := common.ExpandStringList(boundAwsAccountIdSet.List())
	stsUrl := d.Get("sts_url").(string)
	boundArnSet := d.Get("bound_arn").(*schema.Set)
	boundArn := common.ExpandStringList(boundArnSet.List())
	boundRoleNameSet := d.Get("bound_role_name").(*schema.Set)
	boundRoleName := common.ExpandStringList(boundRoleNameSet.List())
	boundRoleIdSet := d.Get("bound_role_id").(*schema.Set)
	boundRoleId := common.ExpandStringList(boundRoleIdSet.List())
	boundResourceIdSet := d.Get("bound_resource_id").(*schema.Set)
	boundResourceId := common.ExpandStringList(boundResourceIdSet.List())
	boundUserNameSet := d.Get("bound_user_name").(*schema.Set)
	boundUserName := common.ExpandStringList(boundUserNameSet.List())
	boundUserIdSet := d.Get("bound_user_id").(*schema.Set)
	boundUserId := common.ExpandStringList(boundUserIdSet.List())
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.AuthMethodCreateAwsIam{
		Name:              name,
		BoundAwsAccountId: boundAwsAccountId,
		Token:             &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.StsUrl, stsUrl)
	common.GetAkeylessPtr(&body.BoundArn, boundArn)
	common.GetAkeylessPtr(&body.BoundRoleName, boundRoleName)
	common.GetAkeylessPtr(&body.BoundRoleId, boundRoleId)
	common.GetAkeylessPtr(&body.BoundResourceId, boundResourceId)
	common.GetAkeylessPtr(&body.BoundUserName, boundUserName)
	common.GetAkeylessPtr(&body.BoundUserId, boundUserId)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	rOut, _, err := client.AuthMethodCreateAwsIam(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create auth method: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create auth method: %v", err)
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

func resourceAuthMethodAwsIamRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.AccessInfo.AwsIamAccessRules.AccountId != nil {
		err = d.Set("bound_aws_account_id", *rOut.AccessInfo.AwsIamAccessRules.AccountId)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AwsIamAccessRules.StsEndpoint != nil {
		err = d.Set("sts_url", *rOut.AccessInfo.AwsIamAccessRules.StsEndpoint)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AwsIamAccessRules.Arn != nil {
		err = d.Set("bound_arn", *rOut.AccessInfo.AwsIamAccessRules.Arn)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AwsIamAccessRules.RoleName != nil {
		err = d.Set("bound_role_name", *rOut.AccessInfo.AwsIamAccessRules.RoleName)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AwsIamAccessRules.RoleId != nil {
		err = d.Set("bound_role_id", *rOut.AccessInfo.AwsIamAccessRules.RoleId)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AwsIamAccessRules.ResourceId != nil {
		err = d.Set("bound_resource_id", *rOut.AccessInfo.AwsIamAccessRules.ResourceId)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AwsIamAccessRules.UserName != nil {
		err = d.Set("bound_user_name", *rOut.AccessInfo.AwsIamAccessRules.UserName)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AwsIamAccessRules.UserId != nil {
		err = d.Set("bound_user_id", *rOut.AccessInfo.AwsIamAccessRules.UserId)
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

func resourceAuthMethodAwsIamUpdate(d *schema.ResourceData, m interface{}) error {
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
	boundAwsAccountIdSet := d.Get("bound_aws_account_id").(*schema.Set)
	boundAwsAccountId := common.ExpandStringList(boundAwsAccountIdSet.List())
	stsUrl := d.Get("sts_url").(string)
	boundArnSet := d.Get("bound_arn").(*schema.Set)
	boundArn := common.ExpandStringList(boundArnSet.List())
	boundRoleNameSet := d.Get("bound_role_name").(*schema.Set)
	boundRoleName := common.ExpandStringList(boundRoleNameSet.List())
	boundRoleIdSet := d.Get("bound_role_id").(*schema.Set)
	boundRoleId := common.ExpandStringList(boundRoleIdSet.List())
	boundResourceIdSet := d.Get("bound_resource_id").(*schema.Set)
	boundResourceId := common.ExpandStringList(boundResourceIdSet.List())
	boundUserNameSet := d.Get("bound_user_name").(*schema.Set)
	boundUserName := common.ExpandStringList(boundUserNameSet.List())
	boundUserIdSet := d.Get("bound_user_id").(*schema.Set)
	boundUserId := common.ExpandStringList(boundUserIdSet.List())
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.AuthMethodUpdateAwsIam{
		Name:              name,
		BoundAwsAccountId: boundAwsAccountId,
		Token:             &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.StsUrl, stsUrl)
	common.GetAkeylessPtr(&body.BoundArn, boundArn)
	common.GetAkeylessPtr(&body.BoundRoleName, boundRoleName)
	common.GetAkeylessPtr(&body.BoundRoleId, boundRoleId)
	common.GetAkeylessPtr(&body.BoundResourceId, boundResourceId)
	common.GetAkeylessPtr(&body.BoundUserName, boundUserName)
	common.GetAkeylessPtr(&body.BoundUserId, boundUserId)
	common.GetAkeylessPtr(&body.NewName, name)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.AuthMethodUpdateAwsIam(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodAwsIamDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceAuthMethodAwsIamImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAuthMethodAwsIamRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
