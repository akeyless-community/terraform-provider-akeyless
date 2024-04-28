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

func resourceGcpTarget() *schema.Resource {
	return &schema.Resource{
		Description: "GCP Target resource",
		Create:      resourceGcpTargetCreate,
		Read:        resourceGcpTargetRead,
		Update:      resourceGcpTargetUpdate,
		Delete:      resourceGcpTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGcpTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"gcp_sa_email": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "GCP service account email",
			},
			"gcp_key": {
				Type:        schema.TypeString,
				Sensitive:   true,
				Optional:    true,
				Description: "Base64-encoded service account private key text",
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
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
		},
	}
}

func resourceGcpTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	gcpKey := d.Get("gcp_key").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	key := d.Get("key").(string)
	comment := d.Get("comment").(string)
	description := d.Get("description").(string)

	body := akeyless.CreateGcpTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GcpKey, gcpKey)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Comment, comment)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.CreateGcpTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceGcpTargetRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.Value != nil {
		if rOut.Value.GcpTargetDetails.GcpServiceAccountEmail != nil {
			err = d.Set("gcp_sa_email", *rOut.Value.GcpTargetDetails.GcpServiceAccountEmail)
			if err != nil {
				return err
			}
		}
		if rOut.Value.GcpTargetDetails.GcpServiceAccountKey != nil {
			err = d.Set("gcp_key", *rOut.Value.GcpTargetDetails.GcpServiceAccountKeyBase64)
			if err != nil {
				return err
			}
		}
		if rOut.Value.GcpTargetDetails.UseGwCloudIdentity != nil {
			err = d.Set("use_gw_cloud_identity", *rOut.Value.GcpTargetDetails.UseGwCloudIdentity)
			if err != nil {
				return err
			}
		}
	}

	if rOut.Target != nil {
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
	}

	d.SetId(path)

	return nil
}

func resourceGcpTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	gcpKey := d.Get("gcp_key").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	key := d.Get("key").(string)
	comment := d.Get("comment").(string)
	description := d.Get("description").(string)

	body := akeyless.UpdateGcpTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GcpKey, gcpKey)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Comment, comment)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.UpdateGcpTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceGcpTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceGcpTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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
