// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
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
			"connection_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Type of connection [credentials/cloud-identity]",
			},
			"subscription_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure Subscription Id",
			},
			"resource_group_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Resource Group name in your Azure subscription",
			},
			"resource_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of the relevant Resource",
			},
			"use_gw_cloud_identity": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Use the GW's Cloud IAM",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
			"key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "Key name. The key is used to encrypt the target secret value. If the key name is not specified, the account default protection key is used",
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
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	clientId := d.Get("client_id").(string)
	tenantId := d.Get("tenant_id").(string)
	clientSecret := d.Get("client_secret").(string)
	connectionType := d.Get("connection_type").(string)
	subscriptionId := d.Get("subscription_id").(string)
	resourceGroupName := d.Get("resource_group_name").(string)
	resourceName := d.Get("resource_name").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	maxVersions := d.Get("max_versions").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetCreateAzure{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ClientId, clientId)
	common.GetAkeylessPtr(&body.TenantId, tenantId)
	common.GetAkeylessPtr(&body.ClientSecret, clientSecret)
	common.GetAkeylessPtr(&body.ConnectionType, connectionType)
	common.GetAkeylessPtr(&body.SubscriptionId, subscriptionId)
	common.GetAkeylessPtr(&body.ResourceGroupName, resourceGroupName)
	common.GetAkeylessPtr(&body.ResourceName, resourceName)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, resp, err := client.TargetCreateAzure(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceAzureTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get target details", res, err)
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
	if rOut.Value.AzureTargetDetails.AzureSubscriptionId != nil {
		err = d.Set("subscription_id", *rOut.Value.AzureTargetDetails.AzureSubscriptionId)
		if err != nil {
			return err
		}
	}
	if rOut.Value.AzureTargetDetails.AzureResourceGroupName != nil {
		err = d.Set("resource_group_name", *rOut.Value.AzureTargetDetails.AzureResourceGroupName)
		if err != nil {
			return err
		}
	}
	if rOut.Value.AzureTargetDetails.AzureResourceName != nil {
		err = d.Set("resource_name", *rOut.Value.AzureTargetDetails.AzureResourceName)
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
		err := d.Set("description", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceAzureTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	clientId := d.Get("client_id").(string)
	tenantId := d.Get("tenant_id").(string)
	clientSecret := d.Get("client_secret").(string)
	connectionType := d.Get("connection_type").(string)
	subscriptionId := d.Get("subscription_id").(string)
	resourceGroupName := d.Get("resource_group_name").(string)
	resourceName := d.Get("resource_name").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetUpdateAzure{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ClientId, clientId)
	common.GetAkeylessPtr(&body.TenantId, tenantId)
	common.GetAkeylessPtr(&body.ClientSecret, clientSecret)
	common.GetAkeylessPtr(&body.ConnectionType, connectionType)
	common.GetAkeylessPtr(&body.SubscriptionId, subscriptionId)
	common.GetAkeylessPtr(&body.ResourceGroupName, resourceGroupName)
	common.GetAkeylessPtr(&body.ResourceName, resourceName)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, resp, err := client.TargetUpdateAzure(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceAzureTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.TargetDelete{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.TargetDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceAzureTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAzureTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
