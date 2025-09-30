package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
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
            "ignore_cache": {
                Type:        schema.TypeString,
                Optional:    true,
                Description: "Retrieve the Secret value without checking the Gateway's cache [true/false]",
                Default:     "false",
            },
			"value": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The secret contents.",
			},
			"inject_url": {
				Type:        schema.TypeSet,
				Computed:    true,
				Description: "List of URLs associated with the item (relevant only for type 'password')",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"password": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Password value (relevant only for type 'password')",
			},
			"username": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Username value (relevant only for type 'password')",
			},
			"custom_field": {
				Type:        schema.TypeMap,
				Computed:    true,
				Sensitive:   true,
				Description: "Additional custom fields to associate with the item (e.g fieldName1=value1) (relevant only for type 'password')",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key_value_pairs": {
				Type:        schema.TypeMap,
				Computed:    true,
				Sensitive:   true,
				Description: "The key value pairs for key/value secrets.",
				Elem:        &schema.Schema{Type: schema.TypeString},
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
    ignoreCache := d.Get("ignore_cache").(string)

	if version != 0 {
		gsvBody.Version = &version
	}
    if ignoreCache != "" {
        gsvBody.IgnoreCache = &ignoreCache
    }

	gsvOut, _, err := client.GetSecretValue(ctx).Body(gsvBody).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't get Secret value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get Secret value: %v", err)
	}

	item := akeyless_api.DescribeItem{
		Name:  path,
		Token: &token,
	}

	itemOut, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return err
	}

	secretType := itemOut.ItemSubType
	value := gsvOut[path]

	err = d.Set("version", version)
	if err != nil {
		return err
	}
	err = d.Set("value", value)
	if err != nil {
		return err
	}

	info := itemOut.ItemGeneralInfo
	format := ""
	if info != nil {
		staticSecretInfo := info.StaticSecretInfo
		if staticSecretInfo != nil {
			if staticSecretInfo.Format != nil {
				format = *staticSecretInfo.Format
			}
			if staticSecretInfo.Websites != nil {
				err := d.Set("inject_url", staticSecretInfo.Websites)
				if err != nil {
					return err
				}
			}
		}
	}

	stringValue, ok := value.(string)
	if !ok {
		return fmt.Errorf("wrong value variable string type")
	}

	if *secretType == "generic" {
		if format == "key-value" {
			var kvValue map[string]any
			err = json.Unmarshal([]byte(stringValue), &kvValue)
			if err != nil {
				return fmt.Errorf("can't convert key value secret value")
			}
			err = d.Set("key_value_pairs", kvValue)
			if err != nil {
				return err
			}
		}
	} else {
		var jsonValue map[string]any
		err = json.Unmarshal([]byte(stringValue), &jsonValue)
		if err != nil {
			return fmt.Errorf("can't convert password secret value")
		}
		err = d.Set("password", jsonValue["password"])
		if err != nil {
			return err
		}
		err = d.Set("username", jsonValue["username"])
		if err != nil {
			return err
		}
		// Remove separate fields from the custom_field map
		delete(jsonValue, "username")
		delete(jsonValue, "password")
		err = d.Set("custom_field", jsonValue)
		if err != nil {
			return err
		}
	}

	d.SetId(path)
	return nil
}
