package akeyless

import (
	"context"
	"errors"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceSecret() *schema.Resource {
	return &schema.Resource{
		Description: "Reads any secret data (currently support Static/Dynamic)",
		Read:        dataSourceSecretRead,
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path where the secret is stored",
			},
			"value": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The secret contents",
			},
			"version": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The version of the secret.",
			},
		},
	}
}

func dataSourceSecretRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)

	itemBody := akeyless_api.DescribeItem{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	var apiErr akeyless_api.GenericOpenAPIError

	itemOut, _, err := client.DescribeItem(ctx).Body(itemBody).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't get Secret item: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get Secret item: %v", err)
	}

	if *itemOut.ItemType == common.StaticSecretType {
		err := dataSourceStaticSecretRead(d, m)
		if err != nil {
			return err
		}
		return nil
	}

	if *itemOut.ItemType == common.DynamicStaticSecretType {
		err := dataSourceDynamicSecretRead(d, m)
		if err != nil {
			return err
		}
		return nil
	}

	if *itemOut.ItemType == common.RotatedSecretType {
		err := dataSourceGetRotatedSecretValueRead(d, m)
		if err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("unsupported Secert type '%v' for %v: %v", *itemOut.ItemType, path, err)
}
