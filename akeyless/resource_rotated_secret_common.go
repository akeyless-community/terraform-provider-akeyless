package akeyless

import (
	"context"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRotatedSecretCommonDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client

	ctx := context.Background()
	token, err := provider.getToken(ctx, d)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	path := d.Id()

	body := akeyless_api.DeleteItem{
		Token: &token,
		Name:  path,
	}

	_, _, err = client.DeleteItem(ctx).Body(body).Execute()
	if err != nil {
		return err
	}

	return nil
}
