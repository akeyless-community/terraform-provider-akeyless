package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestTargetAerospikeResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	targetName := "aerospike_target"
	targetPath := testPath(targetName)
	config := fmt.Sprintf(`
		resource "akeyless_target_aerospike" "%v" {
			name           = "%v"
			hostname       = "127.0.0.1"
			port           = "3000"
			namespace      = "test"
			admin_username = "admin"
			password       = "password"
			description    = "test aerospike target"
		}
	`, targetName, targetPath)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_target_aerospike" "%v" {
			name           = "%v"
			hostname       = "127.0.0.1"
			port           = "3000"
			namespace      = "test"
			admin_username = "admin"
			password       = "password"
			description    = "updated aerospike target"
		}
	`, targetName, targetPath)

	testutils.TesTargetResource(t, providerFactories, config, configUpdate, targetPath)
}
