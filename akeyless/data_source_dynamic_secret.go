package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
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
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	gsvBody := akeyless_api.GetDynamicSecretValue{
		Name:  path,
		Token: &token,
	}
	var gsvOutIntr map[string]interface{}

	gsvOut, _, err := client.GetDynamicSecretValue(ctx).Body(gsvBody).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			bo := apiErr.Body()
			err = json.Unmarshal(bo, &gsvOutIntr)
			if err != nil {
				return fmt.Errorf("can't get Dynamic Secret value: %v", string(bo))
			}
		} else {
			return fmt.Errorf("can't get Dynamic Secret value: %v", err)
		}
	}
	var marshal []byte

	if gsvOutIntr != nil {
		gsvOut = make(map[string]interface{})
		for k, val := range gsvOutIntr {
			if v, ok := val.(string); ok {
				gsvOut[k] = v
			} else {
				ma, err := json.Marshal(val)
				if err != nil {
					return err
				}
				gsvOut[k] = string(ma)
			}
		}
	}

	if gsvOut != nil {
		marshal, err = json.Marshal(gsvOut)
		if err != nil {
			return err
		}
	}
	err = d.Set("value", string(marshal))
	if err != nil {
		return err
	}

	d.SetId(path)

	return nil
}
