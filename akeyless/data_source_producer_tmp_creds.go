package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGatewayGetProducerTmpCreds() *schema.Resource {
	return &schema.Resource{
		Description: "Get producer temporary credentials list data source",
		Read:        dataSourceGatewayGetProducerTmpCredsRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Producer Name",
				ForceNew:    true,
			},
			"value": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
		},
	}
}

func dataSourceGatewayGetProducerTmpCredsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client

	ctx := context.Background()
	token, err := provider.getToken(ctx, d)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	var apiErr akeyless_api.GenericOpenAPIError

	name := d.Get("name").(string)

	body := akeyless_api.GatewayGetTmpUsers{
		Name:  name,
		Token: &token,
	}

	rOut, res, err := client.GatewayGetTmpUsers(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}
	marshalValue, err := json.Marshal(rOut)
	if err != nil {
		return err
	}
	err = d.Set("value", string(marshalValue))
	if err != nil {
		return err
	}

	d.SetId(name)
	return nil
}
