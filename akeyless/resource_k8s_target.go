// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceK8sTarget() *schema.Resource {
	return &schema.Resource{
		Description: "K8S Target resource",
		Create:      resourceK8sTargetCreate,
		Read:        resourceK8sTargetRead,
		Update:      resourceK8sTargetUpdate,
		Delete:      resourceK8sTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceK8sTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"k8s_cluster_endpoint": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "K8S Cluster endpoint. https:// , <DNS / IP> of the cluster.",
			},
			"k8s_cluster_ca_cert": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "K8S Cluster certificate. Base 64 encoded certificate.",
			},
			"k8s_cluster_token": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "K8S Cluster authentication token.",
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

func resourceK8sTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	k8sClusterEndpoint := d.Get("k8s_cluster_endpoint").(string)
	k8sClusterCaCert := d.Get("k8s_cluster_ca_cert").(string)
	k8sClusterToken := d.Get("k8s_cluster_token").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetCreateK8s{
		Name:               name,
		K8sClusterEndpoint: k8sClusterEndpoint,
		K8sClusterCaCert:   k8sClusterCaCert,
		K8sClusterToken:    k8sClusterToken,
		Token:              &token,
	}
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.TargetCreateK8s(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceK8sTargetRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.Value.NativeK8sTargetDetails.K8sClusterEndpoint != nil {
		err = d.Set("k8s_cluster_endpoint", *rOut.Value.NativeK8sTargetDetails.K8sClusterEndpoint)
		if err != nil {
			return err
		}
	}
	if rOut.Value.NativeK8sTargetDetails.K8sClusterCaCertificate != nil {
		err = d.Set("k8s_cluster_ca_cert", *rOut.Value.NativeK8sTargetDetails.K8sClusterCaCertificate)
		if err != nil {
			return err
		}
	}
	if rOut.Value.NativeK8sTargetDetails.K8sBearerToken != nil {
		err = d.Set("k8s_cluster_token", *rOut.Value.NativeK8sTargetDetails.K8sBearerToken)
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

func resourceK8sTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	k8sClusterEndpoint := d.Get("k8s_cluster_endpoint").(string)
	k8sClusterCaCert := d.Get("k8s_cluster_ca_cert").(string)
	k8sClusterToken := d.Get("k8s_cluster_token").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetUpdateK8s{
		Name:               name,
		K8sClusterEndpoint: k8sClusterEndpoint,
		K8sClusterCaCert:   k8sClusterCaCert,
		K8sClusterToken:    k8sClusterToken,
		Token:              &token,
	}
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.TargetUpdateK8s(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceK8sTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceK8sTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceK8sTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
