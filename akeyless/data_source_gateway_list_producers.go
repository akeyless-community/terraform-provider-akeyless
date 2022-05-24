package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGatewayListProducers() *schema.Resource {
	return &schema.Resource{
		Description: "List available producers data source",
		Read:        dataSourceGatewayListProducersRead,
		Schema: map[string]*schema.Schema{
			"producers": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"producers_errors": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
		},
	}
}

func dataSourceGatewayListProducersRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	body := akeyless.GatewayListProducers{
		Token: &token,
	}

	rOut, res, err := client.GatewayListProducers(ctx).Body(body).Execute()
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
	marshalProducers, err := json.Marshal(rOut.Producers)
	if err != nil {
		return err
	}
	err = d.Set("producers", string(marshalProducers))
	if err != nil {
		return err
	}
	marshalProducersErrors, err := json.Marshal(rOut.ProducersErrors)
	if err != nil {
		return err
	}
	err = d.Set("producers_errors", string(marshalProducersErrors))
	if err != nil {
		return err
	}

	return nil
}
