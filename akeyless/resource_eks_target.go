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

func resourceEksTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
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
	comment := d.Get("comment").(string)
	description := d.Get("description").(string)

	body := akeyless.CreateEKSTarget{
		Name:               name,
		EksClusterName:     eksClusterName,
		EksClusterEndpoint: eksClusterEndpoint,
		EksClusterCaCert:   eksClusterCaCert,
		Token:              &token,
	}
	common.GetAkeylessPtr(&body.EksAccessKeyId, eksAccessKeyId)
	common.GetAkeylessPtr(&body.EksSecretAccessKey, eksSecretAccessKey)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.EksRegion, eksRegion)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Comment, comment)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.CreateEKSTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceEksTargetRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.Value.EksClusterName != nil {
		err = d.Set("eks_cluster_name", *rOut.Value.EksClusterName)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksClusterEndpoint != nil {
		err = d.Set("eks_cluster_endpoint", *rOut.Value.EksClusterEndpoint)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksClusterCaCertificate != nil {
		err = d.Set("eks_cluster_ca_cert", *rOut.Value.EksClusterCaCertificate)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksAccessKeyId != nil {
		err = d.Set("eks_access_key_id", *rOut.Value.EksAccessKeyId)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksSecretAccessKey != nil {
		err = d.Set("eks_secret_access_key", *rOut.Value.EksSecretAccessKey)
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
	if rOut.Value.EksRegion != nil {
		err = d.Set("eks_region", *rOut.Value.EksRegion)
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

func resourceEksTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
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
	comment := d.Get("comment").(string)
	description := d.Get("description").(string)

	body := akeyless.UpdateEKSTarget{
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
	common.GetAkeylessPtr(&body.Comment, comment)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.UpdateEKSTarget(ctx).Body(body).Execute()
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

func resourceEksTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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
