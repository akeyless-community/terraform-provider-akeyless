package akeyless

import (
	"context"

	"github.com/akeylesslabs/akeyless-go/v4"
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
