package akeyless

import (
	"context"
	"errors"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
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
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "The id of the item",
						},
						"name": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The name (full path) of the item",
						},
						"type": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The type of the item",
						},
						"display_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The display id of the item",
						},
						"last_version": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "The last version of the item",
						},
						"is_enabled": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "Indicates if the item is enabled",
						},
					},
				},
				Description: "List of items on a given path",
			},
		},
	}
}

func dataSourceItemsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	body := akeyless_api.ListItems{
		Token: &token,
		Path:  &path,
	}

	nliOut, _, err := client.ListItems(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't list items: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't list items: %v", err)
	}

	items := make([]map[string]interface{}, 0)
	for _, item := range nliOut.Items {
		itemMap := map[string]interface{}{}
		if item.ItemId != nil {
			itemMap["id"] = *item.ItemId
		}
		if item.ItemName != nil {
			itemMap["name"] = *item.ItemName
		}
		if item.ItemType != nil {
			itemMap["type"] = *item.ItemType
		}
		if item.DisplayId != nil {
			itemMap["display_id"] = *item.DisplayId
		}
		if item.LastVersion != nil {
			itemMap["last_version"] = *item.LastVersion
		}
		if item.IsEnabled != nil {
			itemMap["is_enabled"] = *item.IsEnabled
		}
		items = append(items, itemMap)
	}

	if err := d.Set("items", items); err != nil {
		return fmt.Errorf("error setting items: %s", err)
	}

	d.SetId(path)

	return nil
}
