package akeyless

import (
	"context"
	"encoding/json"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
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
				Description: "JSON-encoded list of temporary credentials data",
			},
		},
	}
}

func dataSourceGatewayGetProducerTmpCredsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.GatewayGetTmpUsers{
		Name:  name,
		Token: &token,
	}

	rOut, res, err := client.GatewayGetTmpUsers(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get value", res, err)
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
