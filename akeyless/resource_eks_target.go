package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceEksTarget() *schema.Resource {
	return &schema.Resource{
		Description: "EKS Target resource",
		Create:      resourceEksTargetCreate,
		Read:        resourceEksTargetRead,
		Update:      resourceEksTargetUpdate,
		Delete:      resourceEksTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceEksTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"eks_cluster_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "EKS cluster name",
			},
			"eks_cluster_endpoint": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "EKS cluster endpoint (i.e., https://<IP> of the cluster)",
			},
			"eks_cluster_ca_cert": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "EKS cluster base-64 encoded certificate",
			},
			"eks_access_key_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "EKS access key ID",
			},
			"eks_secret_access_key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "EKS secret access key",
			},
			"use_gw_cloud_identity": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Use the GW's Cloud IAM",
			},
			"eks_region": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "EKS region",
				Default:     "us-east-2",
			},
			"key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
		},
	}
}

func resourceEksTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	eksClusterName := d.Get("eks_cluster_name").(string)
	eksClusterEndpoint := d.Get("eks_cluster_endpoint").(string)
	eksClusterCaCert := d.Get("eks_cluster_ca_cert").(string)
	eksAccessKeyId := d.Get("eks_access_key_id").(string)
	eksSecretAccessKey := d.Get("eks_secret_access_key").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	eksRegion := d.Get("eks_region").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetCreateEks{
		Name:               name,
		EksClusterName:     eksClusterName,
		EksClusterEndpoint: eksClusterEndpoint,
		EksClusterCaCert:   eksClusterCaCert,
		EksAccessKeyId:     eksAccessKeyId,
		EksSecretAccessKey: eksSecretAccessKey,
		Token:              &token,
	}
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.EksRegion, eksRegion)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.TargetCreateEks(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Target: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Target: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceEksTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
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

	if rOut.Value.EksTargetDetails.EksClusterName != nil {
		err = d.Set("eks_cluster_name", *rOut.Value.EksTargetDetails.EksClusterName)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksTargetDetails.EksClusterEndpoint != nil {
		err = d.Set("eks_cluster_endpoint", *rOut.Value.EksTargetDetails.EksClusterEndpoint)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksTargetDetails.EksClusterCaCertificate != nil {
		err = d.Set("eks_cluster_ca_cert", *rOut.Value.EksTargetDetails.EksClusterCaCertificate)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksTargetDetails.EksAccessKeyId != nil {
		err = d.Set("eks_access_key_id", *rOut.Value.EksTargetDetails.EksAccessKeyId)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksTargetDetails.EksSecretAccessKey != nil {
		err = d.Set("eks_secret_access_key", *rOut.Value.EksTargetDetails.EksSecretAccessKey)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksTargetDetails.UseGwCloudIdentity != nil {
		err = d.Set("use_gw_cloud_identity", *rOut.Value.EksTargetDetails.UseGwCloudIdentity)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksTargetDetails.EksRegion != nil {
		err = d.Set("eks_region", *rOut.Value.EksTargetDetails.EksRegion)
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

func resourceEksTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	eksClusterName := d.Get("eks_cluster_name").(string)
	eksClusterEndpoint := d.Get("eks_cluster_endpoint").(string)
	eksClusterCaCert := d.Get("eks_cluster_ca_cert").(string)
	eksAccessKeyId := d.Get("eks_access_key_id").(string)
	eksSecretAccessKey := d.Get("eks_secret_access_key").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	eksRegion := d.Get("eks_region").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetUpdateEks{
		Name:               name,
		EksClusterName:     eksClusterName,
		EksClusterEndpoint: eksClusterEndpoint,
		EksClusterCaCert:   eksClusterCaCert,
		EksAccessKeyId:     eksAccessKeyId,
		EksSecretAccessKey: eksSecretAccessKey,
		Token:              &token,
	}
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.EksRegion, eksRegion)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.TargetUpdateEks(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceEksTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceEksTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceEksTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
