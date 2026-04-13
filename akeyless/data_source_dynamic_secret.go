package akeyless

import (
	"context"
	"encoding/json"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
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
			"args": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Optional arguments as key=value pairs or JSON strings, e.g - \"--args=csr=base64_encoded_csr --args=common_name=bar\" or args='{\"csr\":\"base64_encoded_csr\"}. It is possible to combine both formats.'",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"dbname": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "DBName: Optional override DB name (works only if DS allows it. only relevant for MSSQL)",
			},
			"host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Host",
			},
			"target": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Target Name",
			},
			"timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Timeout in seconds",
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

	ctx := context.Background()
	gsvBody := akeyless_api.GetDynamicSecretValue{
		Name:  path,
		Token: &token,
	}

	if v, ok := d.GetOk("args"); ok {
		args := v.([]any)
		argsStr := make([]string, len(args))
		for i, arg := range args {
			argsStr[i] = arg.(string)
		}
		gsvBody.Args = argsStr
	}

	if v, ok := d.GetOk("dbname"); ok {
		dbname := v.(string)
		gsvBody.Dbname = &dbname
	}

	if v, ok := d.GetOk("host"); ok {
		host := v.(string)
		gsvBody.Host = &host
	}

	if v, ok := d.GetOk("target"); ok {
		target := v.(string)
		gsvBody.Target = &target
	}

	if v, ok := d.GetOk("timeout"); ok {
		timeout := int64(v.(int))
		gsvBody.Timeout = &timeout
	}

	var gsvOutIntr map[string]any

	gsvOut, resp, err := client.GetDynamicSecretValue(ctx).Body(gsvBody).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get dynamic secret value", resp, err)
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
