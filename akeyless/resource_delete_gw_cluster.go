// generated fule
package akeyless

import (
	"context"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayCluster() *schema.Resource {
	return &schema.Resource{
		Description: "Gateway cluster",
		Delete:      resourceGatewayClusterDelete,
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

func resourceGwClusterDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	params := akeyless.DeleteGatewayCluster{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteGatewayCluster(ctx).Body(params).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceGatewayClusterImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	path := d.Id()

	err := d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
