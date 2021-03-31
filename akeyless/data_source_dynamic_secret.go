package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceDynamicSecret() *schema.Resource {
	return &schema.Resource{
		Description: "Dynamic Secret data source",
		Read:        dataSourceDynamicSecretRead,
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path where the secret is stored. Defaults to the latest version.",
			},
			"value": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The secret contents.",
			},
		},
	}
}

func dataSourceDynamicSecretRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	gsvBody := akeyless.GetDynamicSecretValue{
		Name:  path,
		Token: &token,
	}

	gsvOut, _, err := client.GetDynamicSecretValue(ctx).Body(gsvBody).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't get Dynamic Secret value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get Dynamic Secret value: %v", err)
	}

	marshal, err := json.Marshal(gsvOut)
	if err != nil {
		return err
	}

	err = d.Set("value", string(marshal))
	if err != nil {
		return err
	}

	d.SetId(path)

	return nil
}
