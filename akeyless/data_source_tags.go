package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGetTags() *schema.Resource {
	return &schema.Resource{
		Description: "Get tags data source",
		Read:        dataSourceGetTagsRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Item name",
				ForceNew:    true,
			},
			"tags": {
				Type:        schema.TypeSet,
				Computed:    true,
				Required:    false,
				Description: "List of item tags",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceGetTagsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.GetTags{
		Name:  name,
		Token: &token,
	}

	rOut, res, err := client.GetTags(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get value", res, err)
	}
	err = d.Set("tags", rOut)
	if err != nil {
		return err
	}

	d.SetId(name)
	return nil
}
