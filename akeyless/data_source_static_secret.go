package akeyless

import (
	"context"
	"errors"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceStaticSecret() *schema.Resource {
	return &schema.Resource{
		Description: "Static secret data source",
		Read:        dataSourceStaticSecretRead,
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path where the secret is stored. Defaults to the latest version.",
			},
			"version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The version of the secret.",
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

func dataSourceStaticSecretRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	gsvBody := akeyless_api.GetSecretValue{
		Names: []string{path},
		Token: &token,
	}
	version := int32(d.Get("version").(int))

	if version != 0 {
		gsvBody.Version = &version
	}

	gsvOut, _, err := client.GetSecretValue(ctx).Body(gsvBody).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't get Secret value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get Secret value: %v", err)
	}

	err = d.Set("version", version)
	if err != nil {
		return err
	}
	err = d.Set("value", gsvOut[path])
	if err != nil {
		return err
	}

	d.SetId(path)

	return nil
}
