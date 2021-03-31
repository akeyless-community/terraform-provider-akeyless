package akeyless

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"os"

	"testing"
)

var testAccProvider *schema.Provider
var providerFactories map[string]func() (*schema.Provider, error)

func TestMain(m *testing.M) {
	testAccProvider = Provider()
	providerFactories = map[string]func() (*schema.Provider, error){
		"akeyless": func() (*schema.Provider, error) {
			return testAccProvider, nil
		},
	}

	os.Setenv("API_KEY_LOGIN", "true")
	if os.Getenv("TF_ACC") == "" {
		// short circuit non acceptance test runs
		os.Exit(m.Run())
	}

	resource.TestMain(m)
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func testPath(path string) string {
	return fmt.Sprintf("terraform-tests/%v", path)
}
