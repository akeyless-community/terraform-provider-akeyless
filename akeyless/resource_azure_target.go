// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAzureTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Azure Target resource",
		Create:      resourceAzureTargetCreate,
		Read:        resourceAzureTargetRead,
		Update:      resourceAzureTargetUpdate,
		Delete:      resourceAzureTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAzureTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"client_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Azure client/application id",
			},
			"tenant_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Azure tenant id",
			},
			"client_secret": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Azure client secret",
			},
			"use_gw_cloud_identity": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Use the GW's Cloud IAM",
			},
			"key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Key name. The key is used to encrypt the target secret value. If the key name is not specified, the account default protection key is used",
			},
			"comment": {
				Type:       schema.TypeString,
				Optional:   true,
				Deprecated: "Deprecated: Use description instead",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
		},
	}
}

func resourceAzureTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	clientId := d.Get("client_id").(string)
	tenantId := d.Get("tenant_id").(string)
	clientSecret := d.Get("client_secret").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	key := d.Get("key").(string)
	comment := d.Get("comment").(string)
	description := d.Get("description").(string)

	body := akeyless.CreateAzureTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ClientId, clientId)
	common.GetAkeylessPtr(&body.TenantId, tenantId)
	common.GetAkeylessPtr(&body.ClientSecret, clientSecret)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Comment, comment)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.CreateAzureTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAzureTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GetTargetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GetTargetDetails(ctx).Body(body).Execute()
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

	if rOut.Value.AzureTargetDetails.AzureClientId != nil {
		err = d.Set("client_id", *rOut.Value.AzureTargetDetails.AzureClientId)
		if err != nil {
			return err
		}
	}
	if rOut.Value.AzureTargetDetails.AzureTenantId != nil {
		err = d.Set("tenant_id", *rOut.Value.AzureTargetDetails.AzureTenantId)
		if err != nil {
			return err
		}
	}
	if rOut.Value.AzureTargetDetails.AzureClientSecret != nil {
		err = d.Set("client_secret", *rOut.Value.AzureTargetDetails.AzureClientSecret)
		if err != nil {
			return err
		}
	}
	if rOut.Value.AzureTargetDetails.UseGwCloudIdentity != nil {
		err = d.Set("use_gw_cloud_identity", *rOut.Value.AzureTargetDetails.UseGwCloudIdentity)
		if err != nil {
			return err
		}
	}
	if rOut.Target.ProtectionKeyName != nil {
		err = d.Set("key", *rOut.Target.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.Target.Comment != nil {
		err := common.SetDescriptionBc(d, *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceAzureTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	clientId := d.Get("client_id").(string)
	tenantId := d.Get("tenant_id").(string)
	clientSecret := d.Get("client_secret").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	key := d.Get("key").(string)
	comment := d.Get("comment").(string)
	description := d.Get("description").(string)

	body := akeyless.UpdateAzureTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ClientId, clientId)
	common.GetAkeylessPtr(&body.TenantId, tenantId)
	common.GetAkeylessPtr(&body.ClientSecret, clientSecret)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Comment, comment)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.UpdateAzureTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAzureTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteTarget{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteTarget(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceAzureTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GetTarget{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GetTarget(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
