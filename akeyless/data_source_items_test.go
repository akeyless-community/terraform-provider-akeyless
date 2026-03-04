package akeyless

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestItemsDataSource(t *testing.T) {

	secretName := "test_items_ds_secret"
	secretPath := testPath(secretName)

	deleteItemIfExists(t, secretPath)

	secret := &testSecret{
		secretName: secretPath,
		value:      "test-value",
	}
	createSecret(t, secret)
	defer deleteItemIfExists(t, secretPath)

	folderPath := "terraform-tests"

	config := fmt.Sprintf(`
		data "akeyless_items" "test" {
			path = "%v"
		}
	`, folderPath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkItemsDataSourceNotEmpty(folderPath),
				),
			},
		},
	})
}

func checkItemsDataSourceNotEmpty(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources["data.akeyless_items.test"]
		if !ok {
			return fmt.Errorf("data source akeyless_items.test not found")
		}

		itemsCount := rs.Primary.Attributes["items.#"]
		if itemsCount == "" || itemsCount == "0" {
			return fmt.Errorf("expected items to be non-empty for path %v", path)
		}

		name := rs.Primary.Attributes["items.0.name"]
		if name == "" {
			return fmt.Errorf("expected first item to have a name")
		}

		itemType := rs.Primary.Attributes["items.0.type"]
		if itemType == "" {
			return fmt.Errorf("expected first item to have a type")
		}

		return nil
	}
}
