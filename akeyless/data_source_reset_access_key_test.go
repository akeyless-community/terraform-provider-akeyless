package akeyless

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccDataSourceResetAccessKey_createAndReset(t *testing.T) {
	rand := acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum)
	name := testPath(fmt.Sprintf("reset-ak/%s", rand))

	cfg := fmt.Sprintf(`
	resource "akeyless_auth_method_api_key" "am" {
  		name = "%s"
	}

	data "akeyless_reset_access_key" "test" {
		name = akeyless_auth_method_api_key.am.name
	}
	`, name)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("akeyless_auth_method_api_key.am", "access_key"),
					resource.TestCheckResourceAttrSet("data.akeyless_reset_access_key.test", "new_access_key"),
					testCheckNewKeyDifferentFromOld(),
				),
			},
		},
	})
}

func testCheckNewKeyDifferentFromOld() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ds, ok := s.RootModule().Resources["data.akeyless_reset_access_key.test"]
		if !ok {
			return fmt.Errorf("data source not found in state")
		}
		rs, ok := s.RootModule().Resources["akeyless_auth_method_api_key.am"]
		if !ok {
			return fmt.Errorf("resource not found in state")
		}

		newKey := ds.Primary.Attributes["new_access_key"]
		oldKey := rs.Primary.Attributes["access_key"]
		if newKey == "" || oldKey == "" {
			return fmt.Errorf("expected both keys to be set")
		}
		if newKey == oldKey {
			return fmt.Errorf("expected new access key to differ from original")
		}
		return nil
	}
}
