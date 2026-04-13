package no_gateway

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccountCustomFieldResource(t *testing.T) {
	t.Parallel()

	fieldName := fmt.Sprintf("test_custom_field_%s", testRunID)

	config := fmt.Sprintf(`
		resource "akeyless_account_custom_field" "test" {
			name        = "%s"
			object      = "ITEM"
			object_type = "STATIC_SECRET"
			required    = true
		}
	`, fieldName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_account_custom_field" "test" {
			name        = "%s_updated"
			object_type = "STATIC_SECRET"
			required    = false
		}
	`, fieldName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy: func(s *terraform.State) error {
			client, token, err := testutils.GetClient()
			if err != nil {
				return err
			}
			for _, rs := range s.RootModule().Resources {
				if rs.Type != "akeyless_account_custom_field" {
					continue
				}
				parsedId, err := strconv.ParseInt(rs.Primary.ID, 10, 64)
				if err != nil {
					return fmt.Errorf("invalid id %q: %w", rs.Primary.ID, err)
				}
				body := akeyless_api.AccountCustomFieldGet{
					Id:    parsedId,
					Token: &token,
				}
				_, res, err := client.AccountCustomFieldGet(context.Background()).Body(body).Execute()
				if err == nil {
					return fmt.Errorf("account custom field %s still exists", rs.Primary.ID)
				}
				if res != nil && res.StatusCode != 404 {
					return fmt.Errorf("account custom field %s still exists with status %d", rs.Primary.ID, res.StatusCode)
				}
			}
			return nil
		},
		Steps: []resource.TestStep{
			{Config: config},
			{Config: configUpdate},
		},
	})
}
