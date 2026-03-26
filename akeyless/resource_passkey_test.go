package akeyless

import (
	"fmt"
	"testing"
)

func TestPasskeyResource(t *testing.T) {
	skipIfNoGateway(t)
	t.Parallel()

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

	testItemResource(t, passkeyPath, config, configUpdate)
}

func TestPasskeyResourceEC384(t *testing.T) {
	skipIfNoGateway(t)
	t.Parallel()

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

	testItemResource(t, passkeyPath, config, configUpdate)
}

// Skipping EC512 test - algorithm not supported by API
// func TestPasskeyResourceEC512(t *testing.T) {
// 	t.Parallel()
//
// 	passkeyName := "test_passkey_ec512"
// 	passkeyPath := testPath(passkeyName)
//
// 	config := fmt.Sprintf(`
// 		resource "akeyless_passkey" "%v" {
// 			name 				= "%v"
// 			alg 				= "EC512"
// 			description 		= "Test EC512 passkey"
// 		}
// 	`, passkeyName, passkeyPath)
//
// 	configUpdate := fmt.Sprintf(`
// 		resource "akeyless_passkey" "%v" {
// 			name 				= "%v"
// 			alg 				= "EC512"
// 			description 		= "Updated EC512 passkey"
// 		}
// 	`, passkeyName, passkeyPath)
//
// 	testItemResource(t, passkeyPath, config, configUpdate)
// }
