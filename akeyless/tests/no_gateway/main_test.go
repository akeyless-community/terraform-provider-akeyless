package no_gateway

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var providerFactories map[string]func() (*schema.Provider, error)
var testRunID string

func TestMain(m *testing.M) {
	rand.Seed(time.Now().UnixNano())
	testRunID = fmt.Sprintf("%d", rand.Intn(1000000))
	providerFactories = testutils.NewProviderFactories()
	os.Setenv("API_KEY_LOGIN", "true")
	if os.Getenv("TF_ACC") == "" {
		os.Exit(m.Run())
	}
	if os.Getenv("AKEYLESS_GATEWAY") == "" {
		os.Setenv("AKEYLESS_GATEWAY", "http://127.0.0.1:8081")
	}
	resource.TestMain(m)
}

func testPath(path string) string {
	return testutils.TestPath(testRunID, path)
}
