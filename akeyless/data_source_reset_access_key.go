package akeyless

import (
	"context"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceResetAccessKey() *schema.Resource {
	return &schema.Resource{
		Description: "Reset an Auth Method access key and return the new key",
		Read:        dataSourceResetAccessKeyRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Auth Method name",
			},
			"access_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The newly generated access key",
			},
		},
	}
}

func dataSourceResetAccessKeyRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.ResetAccessKey{
		Name:  name,
		Token: &token,
	}

	rOut, res, err := client.ResetAccessKey(ctx).Body(body).Execute()
	if err != nil {
		if res != nil && res.StatusCode == http.StatusNotFound {
			d.SetId("")
		}
		return common.HandleError("failed to reset access key", res, err)
	}

	if rOut.AccessKey == nil {
		return fmt.Errorf("reset access key succeeded but response did not include a new key")
	}
	if err := d.Set("access_key", rOut.AccessKey); err != nil {
		return err
	}

	d.SetId(name)
	return nil
}
