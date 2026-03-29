package akeyless

import (
	"fmt"
	"math/rand"
	"time"

	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var testAccProvider *schema.Provider
var providerFactories map[string]func() (*schema.Provider, error)
var testRunID string

func TestMain(m *testing.M) {
	// Initialize random seed and generate unique test run ID
	rand.Seed(time.Now().UnixNano())
	testRunID = fmt.Sprintf("%d", rand.Intn(1000000))

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

	if os.Getenv("AKEYLESS_GATEWAY") == "" {
		os.Setenv("AKEYLESS_GATEWAY", "http://127.0.0.1:8081")
	}

	resource.TestMain(m)
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func testPath(path string) string {
	return fmt.Sprintf("terraform-tests/%s/%v", testRunID, path)
}
