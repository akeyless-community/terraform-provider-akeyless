package akeyless

import (
	"context"
	"errors"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceItems() *schema.Resource {
	return &schema.Resource{
		Description: "Get items data source",
		Read:        dataSourceItemsRead,
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path where the items are stored.",
			},
			"items": {
				Type: schema.TypeList,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeInt,
							Required:    true,
							Description: "The id of the item",
						},
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The name (full path) of the item",
						},
						"type": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The type of the item",
						},
						"display_id": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The display id of the item",
						},
						"last_version": {
							Type:        schema.TypeInt,
							Required:    true,
							Description: "The last version of the item",
						},
						"is_enabled": {
							Type:        schema.TypeBool,
							Required:    true,
							Description: "Indicates if the item is enabled",
						},
					},
				},
				Computed:    true,
				Sensitive:   false,
				Description: "List of items on a given path",
			},
		},
	}
}

func dataSourceItemsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	nliBody := akeyless_api.NewListItems()
	nliBody.SetToken(token)
	nliBody.SetPath(path)

	nliOut, _, err := client.ListItems(ctx).Body(*nliBody).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't list items: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't list items: %v", err)
	}

	items := []map[string]interface{}{}
	if nliOut.Items != nil {
		for _, item := range *nliOut.Items {
			itemMap := map[string]interface{}{
				"id":           item.ItemId,
				"name":         item.ItemName,
				"type":         item.ItemType,
				"display_id":   item.DisplayId,
				"last_version": item.LastVersion,
				"is_enabled":   item.IsEnabled,
			}
			items = append(items, itemMap)
		}
	}

	if err := d.Set("items", items); err != nil {
		return fmt.Errorf("error setting items: %s", err)
	}

	d.SetId(path)

	return nil
}
