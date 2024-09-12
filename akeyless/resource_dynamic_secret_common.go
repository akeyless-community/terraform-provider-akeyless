package akeyless

import (
	"context"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client

	ctx := context.Background()
	token, err := provider.getToken(ctx, d)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	path := d.Id()

	deleteItem := akeyless_api.DynamicSecretDelete{
		Token: &token,
		Name:  path,
	}

	_, _, err = client.DynamicSecretDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}
