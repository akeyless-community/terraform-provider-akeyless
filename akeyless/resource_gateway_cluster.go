// generated fule
package akeyless

import (
	"context"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayCluster() *schema.Resource {
	return &schema.Resource{
		Description: "Gateway cluster",
		Create:      resourceGatewayClusterCreate,
		Read:        resourceGatewayClusterRead,
		Update:      resourceGatewayClusterUpdate,
		Delete:      resourceGatewayClusterDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayClusterImport,
		},
		Schema: map[string]*schema.Schema{
			"cluster_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Gateway Cluster, e.g. acc-abcd12345678/p-123456789012/defaultCluster",
			},
			"force_deletion": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Delete cluster even if there is an active gateway or associated secrets. All Gateway secrets will be deleted",
			},
		},
	}
}

func resourceGatewayClusterCreate(d *schema.ResourceData, m interface{}) error { return nil }
func resourceGatewayClusterRead(d *schema.ResourceData, m interface{}) error   { return nil }
func resourceGatewayClusterUpdate(d *schema.ResourceData, m interface{}) error { return nil }

func resourceGatewayClusterDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	clusterName := d.Get("cluster_name").(string)
	forceDeletion := d.Get("force_deletion").(bool)

	body := akeyless.DeleteGwCluster{
		Token:       &token,
		ClusterName: clusterName,
	}

	common.GetAkeylessPtr(&body.ForceDeletion, forceDeletion)

	ctx := context.Background()
	_, _, err := client.DeleteGwCluster(ctx).Body(body).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceGatewayClusterImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	clusterName := d.Id()

	err := d.Set("cluster_name", clusterName)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
