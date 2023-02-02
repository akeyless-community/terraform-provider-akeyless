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

func resourceGkeTarget() *schema.Resource {
	return &schema.Resource{
		Description: "GKE Target resource",
		Create:      resourceGkeTargetCreate,
		Read:        resourceGkeTargetRead,
		Update:      resourceGkeTargetUpdate,
		Delete:      resourceGkeTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGkeTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"gke_service_account_email": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "GKE service account email",
			},
			"gke_cluster_endpoint": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "GKE cluster endpoint, i.e., cluster URI https://<DNS/IP>.",
			},
			"gke_cluster_cert": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "GKE Base-64 encoded cluster certificate",
			},
			"gke_account_key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "GKE service account key",
			},
			"gke_cluster_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "GKE cluster name",
			},
			"key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used",
			},
			"use_gw_cloud_identity": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Use the GW's Cloud IAM",
			},
			"comment": {
				Type:        schema.TypeString,
				Optional:    true,
				Deprecated:  "Deprecated: Use description instead",
				Description: "Comment about the target",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
		},
	}
}

func resourceGkeTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	gkeServiceAccountEmail := d.Get("gke_service_account_email").(string)
	gkeClusterEndpoint := d.Get("gke_cluster_endpoint").(string)
	gkeClusterCert := d.Get("gke_cluster_cert").(string)
	gkeAccountKey := d.Get("gke_account_key").(string)
	gkeClusterName := d.Get("gke_cluster_name").(string)
	key := d.Get("key").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	comment := d.Get("comment").(string)
	description := d.Get("description").(string)

	body := akeyless.CreateGKETarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GkeServiceAccountEmail, gkeServiceAccountEmail)
	common.GetAkeylessPtr(&body.GkeClusterEndpoint, gkeClusterEndpoint)
	common.GetAkeylessPtr(&body.GkeClusterCert, gkeClusterCert)
	common.GetAkeylessPtr(&body.GkeAccountKey, gkeAccountKey)
	common.GetAkeylessPtr(&body.GkeClusterName, gkeClusterName)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.Comment, comment)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.CreateGKETarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceGkeTargetRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.Value.GkeServiceAccountName != nil {
		err = d.Set("gke_service_account_email", *rOut.Value.GkeServiceAccountName)
		if err != nil {
			return err
		}
	}
	if rOut.Value.GkeClusterEndpoint != nil {
		err = d.Set("gke_cluster_endpoint", *rOut.Value.GkeClusterEndpoint)
		if err != nil {
			return err
		}
	}
	if rOut.Value.GkeClusterCaCertificate != nil {
		err = d.Set("gke_cluster_cert", *rOut.Value.GkeClusterCaCertificate)
		if err != nil {
			return err
		}
	}
	if rOut.Value.GkeServiceAccountKey != nil {
		err = d.Set("gke_account_key", *rOut.Value.GkeServiceAccountKey)
		if err != nil {
			return err
		}
	}
	if rOut.Value.GkeClusterName != nil {
		err = d.Set("gke_cluster_name", *rOut.Value.GkeClusterName)
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
	if rOut.Value.UseGwCloudIdentity != nil {
		err = d.Set("use_gw_cloud_identity", *rOut.Value.UseGwCloudIdentity)
		if err != nil {
			return err
		}
	}
	if rOut.Target.Comment != nil {
		err = d.Set("description", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceGkeTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	gkeServiceAccountEmail := d.Get("gke_service_account_email").(string)
	gkeClusterEndpoint := d.Get("gke_cluster_endpoint").(string)
	gkeClusterCert := d.Get("gke_cluster_cert").(string)
	gkeAccountKey := d.Get("gke_account_key").(string)
	gkeClusterName := d.Get("gke_cluster_name").(string)
	key := d.Get("key").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	comment := d.Get("comment").(string)
	description := d.Get("description").(string)

	body := akeyless.UpdateGKETarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GkeServiceAccountEmail, gkeServiceAccountEmail)
	common.GetAkeylessPtr(&body.GkeClusterEndpoint, gkeClusterEndpoint)
	common.GetAkeylessPtr(&body.GkeClusterCert, gkeClusterCert)
	common.GetAkeylessPtr(&body.GkeAccountKey, gkeAccountKey)
	common.GetAkeylessPtr(&body.GkeClusterName, gkeClusterName)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.Comment, comment)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.UpdateGKETarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceGkeTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceGkeTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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
