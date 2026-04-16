package no_gateway

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestStaticSecretDataSource(t *testing.T) {
	tests := []struct {
		name         string
		secretType   string
		secretFormat string
		secretValue  string
		username     string
		password     string
		customField  map[string]string
		injectURL    []string
		expect       map[string]interface{}
	}{
		{
			name:         "GenericText",
			secretType:   "generic",
			secretFormat: "text",
			secretValue:  "my value",
			expect: map[string]interface{}{
				"value": "my value",
			},
		},
		{
			name:         "GenericJSON",
			secretType:   "generic",
			secretFormat: "json",
			secretValue:  `{"key1":"value1","key2":"value2"}`,
			expect: map[string]interface{}{
				"key_value_pairs": map[string]interface{}{
					"key1": "value1",
					"key2": "value2",
				},
			},
		},
		{
			name:         "GenericKeyValue",
			secretType:   "generic",
			secretFormat: "key-value",
			secretValue:  `{"key1":"value1","key2":"value2"}`,
			expect: map[string]interface{}{
				"key_value_pairs": map[string]interface{}{
					"key1": "value1",
					"key2": "value2",
				},
			},
		},
		{
			name:         "Password",
			secretType:   "password",
			secretFormat: "",
			secretValue:  "",
			username:     "my username",
			password:     "my password",
			customField:  map[string]string{"field1": "value1", "field2": "value2"},
			injectURL:    []string{"http://example.com"},
			expect: map[string]interface{}{
				"username":     "my username",
				"password":     "my password",
				"custom_field": map[string]interface{}{"field1": "value1", "field2": "value2"},
				"inject_url":   []string{"http://example.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			staticPath := testPath(tt.name)
			testutils.DeleteItemIfExists(t, staticPath)

			secret := &testutils.TestSecret{
				SecretName:  staticPath,
				SecretType:  tt.secretType,
				Format:      tt.secretFormat,
				Value:       tt.secretValue,
				Username:    tt.username,
				Password:    tt.password,
				CustomField: tt.customField,
				InjectUrl:   tt.injectURL,
			}
			testutils.CreateSecret(t, secret)

			config := fmt.Sprintf(`
				data "akeyless_static_secret" "%v" {
					path = "%v"
					ignore_cache = "true"
				}
				output "static_secret" {
					value      = nonsensitive(data.akeyless_static_secret.%v.value)
					sensitive  = false
				}
			`, tt.name, staticPath, tt.name)

			testStaticSecretDataSourceLocal(t, config, tt.expect)
		})
	}
}

func testStaticSecretDataSourceLocal(t *testing.T, config string, expect map[string]interface{}) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkExpectedStash(expect),
				),
			},
		},
	})
}

func checkExpectedStash(expect map[string]interface{}) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		secretDetails := s.Modules[0].Outputs["static_secret"]
		if secretDetails == nil {
			return fmt.Errorf("target details not shown in terraform output")
		}
		for key, val := range expect {
			switch key {
			case "value":
				value, ok := secretDetails.Value.(string)
				if !ok {
					return fmt.Errorf("wrong value variable type")
				}
				if val != value {
					return fmt.Errorf("value is not equal\nexpect: %v\nactual: %v", val, value)
				}
			case "key_value_pairs":
				value, err := convertToMapStringAny(secretDetails.Value)
				if err != nil {
					return fmt.Errorf("wrong value variable type: %v", err)
				}
				for expectedKey, expectedValue := range val.(map[string]interface{}) {
					actualValue, exists := value[expectedKey]
					if !exists {
						return fmt.Errorf("key %s not found in value", expectedKey)
					}
					if actualValue != expectedValue {
						return fmt.Errorf("value for key %s is not equal\nexpect: %v\nactual: %v", expectedKey, expectedValue, actualValue)
					}
				}
			case "username":
				innerStateValue := s.Modules[0].Resources["data.akeyless_static_secret.Password"].Primary.Attributes["username"]
				if val != innerStateValue {
					return fmt.Errorf("username is not equal\nexpect: %v\nactual: %v", val, innerStateValue)
				}
				value, err := convertToMapStringAny(secretDetails.Value)
				if err != nil {
					return fmt.Errorf("wrong value variable type: %v", err)
				}
				username, ok := value["username"].(string)
				if !ok {
					return fmt.Errorf("wrong username variable type")
				}
				if val != username {
					return fmt.Errorf("username is not equal\nexpect: %v\nactual: %v", val, username)
				}
			case "password":
				innerStateValue := s.Modules[0].Resources["data.akeyless_static_secret.Password"].Primary.Attributes["password"]
				if val != innerStateValue {
					return fmt.Errorf("password is not equal\nexpect: %v\nactual: %v", val, innerStateValue)
				}
				value, err := convertToMapStringAny(secretDetails.Value)
				if err != nil {
					return fmt.Errorf("wrong value variable type: %v", err)
				}
				password, ok := value["password"].(string)
				if !ok {
					return fmt.Errorf("wrong password variable type")
				}
				if val != password {
					return fmt.Errorf("password is not equal\nexpect: %v\nactual: %v", val, password)
				}
			case "custom_field":
				att := s.Modules[0].Resources["data.akeyless_static_secret.Password"].Primary.Attributes
				custoFieldCount, ok := att["custom_field.%"]
				if !ok {
					return fmt.Errorf("custom_field.%% not found in attributes")
				}
				if custoFieldCount == "" {
					return fmt.Errorf("custom_field.%% is empty, expected non-empty map")
				}
				custoFieldCountInt, err := strconv.Atoi(custoFieldCount)
				if err != nil {
					return fmt.Errorf("wrong custom_field count variable type: %v", err)
				}
				if custoFieldCountInt == 0 {
					return fmt.Errorf("custom_field count is zero, expected non-zero map")
				}
				if custoFieldCountInt != len(val.(map[string]interface{})) {
					return fmt.Errorf("custom_field count mismatch\nexpect: %d\nactual: %d", custoFieldCountInt, len(val.(map[string]interface{})))
				}
				for k, v := range att {
					if strings.HasPrefix(k, "custom_field.") {
						key2 := strings.TrimPrefix(k, "custom_field.")
						if key2 == "%" {
							continue
						}
						expectedValue, exists := val.(map[string]interface{})[key2]
						if !exists {
							return fmt.Errorf("custom field %s not found in expected value", key2)
						}
						if v != expectedValue {
							return fmt.Errorf("value for custom field %s is not equal\nexpect: %v\nactual: %v", key2, expectedValue, v)
						}
					}
				}
			case "inject_url":
				att := s.Modules[0].Resources["data.akeyless_static_secret.Password"].Primary.Attributes
				inJectUrlCount, ok := att["inject_url.#"]
				if !ok {
					return fmt.Errorf("inject_url.# not found in attributes")
				}
				if inJectUrlCount == "" {
					return fmt.Errorf("inject_url.# is empty, expected non-empty list")
				}
				inJectUrlCountInt, err := strconv.Atoi(inJectUrlCount)
				if err != nil {
					return fmt.Errorf("wrong inject_url count variable type: %v", err)
				}
				for i := 0; i < inJectUrlCountInt; i++ {
					injectUrlKey := fmt.Sprintf("inject_url.%d", i)
					injectUrlValue, ok := att[injectUrlKey]
					if !ok {
						return fmt.Errorf("inject_url.%d not found in attributes", i)
					}
					found := false
					for _, expectedValue := range val.([]string) {
						if injectUrlValue == expectedValue {
							found = true
							break
						}
					}
					if !found {
						return fmt.Errorf("inject_url value %s not found in expected list", injectUrlValue)
					}
				}
			default:
				return fmt.Errorf("unknown key type: %s", key)
			}
		}
		return nil
	}
}

func convertToMapStringAny(str any) (map[string]any, error) {
	if str == nil {
		return nil, nil
	}
	var s string
	var ok bool
	if s, ok = str.(string); !ok {
		return nil, fmt.Errorf("expected string, got %v", str)
	}
	var m map[string]any
	err := json.Unmarshal([]byte(s), &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}
