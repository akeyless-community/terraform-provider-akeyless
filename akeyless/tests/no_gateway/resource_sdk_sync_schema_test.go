package no_gateway

import (
	"testing"

	akeyless "github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
)

const sdkSyncResourceConfigExamples = `
resource "akeyless_auth_method_alicloud" "test" {}
resource "akeyless_dynamic_secret_aerospike" "test" {}
resource "akeyless_rotated_secret_aerospike" "test" {}
resource "akeyless_rotated_secret_f5_big_ip" "test" {}
resource "akeyless_target_aerospike" "test" {}
resource "akeyless_target_f5_big_ip" "test" {}
`

func TestSDKSyncResourcesRegistered(t *testing.T) {
	provider := akeyless.Provider()
	for _, name := range []string{
		"akeyless_auth_method_alicloud",
		"akeyless_dynamic_secret_aerospike",
		"akeyless_rotated_secret_aerospike",
		"akeyless_rotated_secret_f5_big_ip",
		"akeyless_target_aerospike",
		"akeyless_target_f5_big_ip",
	} {
		if _, ok := provider.ResourcesMap[name]; !ok {
			t.Errorf("resource %q is not registered", name)
		}
	}
}

func TestSDKSyncSensitiveFields(t *testing.T) {
	provider := akeyless.Provider()
	for resourceName, fields := range map[string][]string{
		"akeyless_auth_method_alicloud": {
			"name",
		},
		"akeyless_dynamic_secret_aerospike": {
			"name",
		},
		"akeyless_rotated_secret_aerospike": {
			"rotated_password",
		},
		"akeyless_rotated_secret_f5_big_ip": {
			"rotated_username",
			"rotated_password",
		},
		"akeyless_target_aerospike": {
			"password",
			"aerospike_client_secret",
			"client_private_key",
		},
		"akeyless_target_f5_big_ip": {
			"username",
			"password",
		},
	} {
		resource := provider.ResourcesMap[resourceName]
		for _, field := range fields {
			if resource.Schema[field] == nil {
				t.Errorf("resource %q is missing field %q", resourceName, field)
				continue
			}
			if field != "name" && !resource.Schema[field].Sensitive {
				t.Errorf("resource %q field %q must be sensitive", resourceName, field)
			}
		}
	}
}
