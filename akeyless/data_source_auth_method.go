package akeyless

import (
	"context"
	"errors"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceAuthMethod() *schema.Resource {
	return &schema.Resource{
		Description: "Auth Method data source",
		Read:        dataSourceAuthMethodRead,
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path where the secret is stored. Defaults to the latest version.",
			},
			"account_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The version of the secret.",
			},
			"access_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The version of the secret.",
			},
		},
	}
}

func dataSourceAuthMethodRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	gsvBody := akeyless_api.GetAuthMethod{
		Name:  path,
		Token: &token,
	}

	gsvOut, _, err := client.GetAuthMethod(ctx).Body(gsvBody).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't get Auth Method: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get Auth Method: %v", err)
	}

	err = d.Set("account_id", gsvOut.AccountId)
	if err != nil {
		return err
	}
	err = d.Set("access_id", gsvOut.AuthMethodAccessId)
	if err != nil {
		return err
	}

	d.SetId(path)

	return nil
}
