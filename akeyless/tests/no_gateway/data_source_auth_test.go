package no_gateway

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAuthDataSource(t *testing.T) {
	t.Parallel()

	accessID := os.Getenv("AKEYLESS_ACCESS_ID")
	accessKey := os.Getenv("AKEYLESS_ACCESS_KEY")
	if accessID == "" || accessKey == "" {
		t.Skip("skipping: AKEYLESS_ACCESS_ID and AKEYLESS_ACCESS_KEY must be set")
	}

	config := fmt.Sprintf(`
		data "akeyless_auth" "auth_ds" {
			api_key_login {
				access_id  = %q
				access_key = %q
			}
		}
	`, accessID, accessKey)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.akeyless_auth.auth_ds", "token"),
				),
			},
		},
	})
}
