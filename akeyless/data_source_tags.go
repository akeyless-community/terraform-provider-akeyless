package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGetTags() *schema.Resource {
	return &schema.Resource{
		Description: "Get Auth Method details data source",
		Read:        dataSourceGetTagsRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The item name",
				ForceNew:    true,
			},
			"tags": {
				Type:        schema.TypeSet,
				Computed:    true,
				Required:    false,
				Description: "",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceGetTagsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless.GetTags{
		Name:  name,
		Token: &token,
	}

	rOut, res, err := client.GetTags(ctx).Body(body).Execute()
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
	err = d.Set("tags", rOut)
	if err != nil {
		return err
	}

	d.SetId(name)
	return nil
}
