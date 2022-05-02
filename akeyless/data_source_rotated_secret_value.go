package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGetRotatedSecretValue() *schema.Resource {
	return &schema.Resource{
		Description: "Get rotated secret value data source",
		Read:        dataSourceGetRotatedSecretValueRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Secret name",
				ForceNew:    true,
			},
			"version": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Secret version",
			},
			"value": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "output",
				Sensitive:   true,
			},
		},
	}
}

func dataSourceGetRotatedSecretValueRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	names := d.Get("name").(string)
	version := d.Get("version").(int)

	body := akeyless.GetRotatedSecretValue{
		Names: names,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Version, version)

	rOut, res, err := client.GetRotatedSecretValue(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			err = json.Unmarshal(apiErr.Body(), &rOut)
			err = nil
			if err != nil {
				return fmt.Errorf("can't get value: %v %v", err, string(apiErr.Body()))
			}
		}
		if err != nil {
			return fmt.Errorf("can't get value: %v", err)
		}
	}
	marshalValue, err := json.Marshal(rOut)
	if err != nil {
		return err
	}
	err = d.Set("value", string(marshalValue))
	if err != nil {
		return err
	}

	d.SetId(names)
	return nil
}
