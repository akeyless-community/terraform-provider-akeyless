package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
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

	switch *itemOut.ItemType {
	case common.StaticSecretType:
		err := getStaticSecretValue(ctx, d, m)
		if err != nil {
			return err
		}
		return nil
	case common.DynamicSecretType:
		err := getDynamicSecretValue(ctx, d, m)
		if err != nil {
			return err
		}
		return nil
	case common.RotatedSecretType:
		err := getRotatedSecretValue(ctx, d, m)
		if err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported secret type '%s' for %s: %w", *itemOut.ItemType, path, err)
	}
}

func getStaticSecretValue(ctx context.Context, d *schema.ResourceData, m any) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)

	gsvBody := akeyless_api.GetSecretValue{
		Names: []string{path},
		Token: &token,
	}

	out, resp, err := client.GetSecretValue(ctx).Body(gsvBody).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get secret value", resp, err)
	}

	// Recently, version is not returned with static secret
	err = d.Set("version", 0)
	if err != nil {
		return err
	}

	err = d.Set("value", out[path])
	if err != nil {
		return err
	}

	d.SetId(path)

	return nil
}

func getDynamicSecretValue(ctx context.Context, d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)

	gsvBody := akeyless_api.GetDynamicSecretValue{
		Name:  path,
		Token: &token,
	}
	var gsvOutIntr map[string]any

	gsvOut, _, err := client.GetDynamicSecretValue(ctx).Body(gsvBody).Execute()
	if err != nil {
		var apiErr akeyless_api.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			bo := apiErr.Body()
			err := json.Unmarshal(bo, &gsvOutIntr)
			if err != nil {
				return fmt.Errorf("can't get dynamic secret value: %v", string(bo))
			}
		} else {
			return fmt.Errorf("can't get dynamic secret value: %v", err)
		}
	}

	if gsvOutIntr != nil {
		gsvOut = make(map[string]any)
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

	var marshal []byte
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

func getRotatedSecretValue(ctx context.Context, d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)

	body := akeyless_api.GetRotatedSecretValue{
		Names: path,
		Token: &token,
	}

	rOut, res, err := client.GetRotatedSecretValue(ctx).Body(body).Execute()
	if err != nil {
		var apiErr akeyless_api.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			err = json.Unmarshal(apiErr.Body(), &rOut)
			if err != nil {
				return fmt.Errorf("can't get rotated secret value: %w: %v", err, string(apiErr.Body()))
			}
		} else {
			return fmt.Errorf("can't get rotated secret value: %w", err)
		}
	}

	marshalValue, err := json.Marshal(rOut)
	if err != nil {
		return fmt.Errorf("can't parse rotated secret value: %w", err)
	}

	err = d.Set("value", string(marshalValue))
	if err != nil {
		return err
	}

	d.SetId(path)

	return nil
}
