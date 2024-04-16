package akeyless

import (
	"context"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DynamicSecretDelete{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DynamicSecretDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceDynamicSecretImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	// TODO TV: change it to DynamicSecretGet
	body := akeyless.GatewayGetProducer{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GatewayGetProducer(ctx).Body(body).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
