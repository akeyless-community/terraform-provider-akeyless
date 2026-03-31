package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestPasskeyResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	passkeyName := "test_passkey"
	passkeyPath := testPath(passkeyName)

	config := fmt.Sprintf(`
		resource "akeyless_passkey" "%v" {
			name 				= "%v"
			alg 				= "EC256"
			description 		= "Test passkey"
			tags 				= ["t1", "t2"]
			delete_protection 	= "true"
		}
	`, passkeyName, passkeyPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_passkey" "%v" {
			name 				= "%v"
			alg 				= "EC256"
			description 		= "Updated passkey"
			tags 				= ["t1", "t3"]
			delete_protection 	= "false"
		}
	`, passkeyName, passkeyPath)

	testutils.TestItemResource(t, providerFactories, passkeyPath, config, configUpdate)
}

func TestPasskeyResourceEC384(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	passkeyName := "test_passkey_ec384"
	passkeyPath := testPath(passkeyName)

	config := fmt.Sprintf(`
		resource "akeyless_passkey" "%v" {
			name 				= "%v"
			alg 				= "EC384"
			description 		= "Test EC384 passkey"
		}
	`, passkeyName, passkeyPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_passkey" "%v" {
			name 				= "%v"
			alg 				= "EC384"
			description 		= "Updated EC384 passkey"
		}
	`, passkeyName, passkeyPath)

	testutils.TestItemResource(t, providerFactories, passkeyPath, config, configUpdate)
}
