package akeyless

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"strconv"
	"strings"
	"testing"
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
			deleteItemIfExists(t, staticPath)

			createSecret(t, staticPath, tt.secretType, tt.secretFormat, tt.secretValue, tt.username, tt.password, tt.customField, tt.injectURL)

			config := fmt.Sprintf(`
				data "akeyless_static_secret" "%v" {
					path = "%v"
				}
				output "static_secret" {
					value      = nonsensitive(data.akeyless_static_secret.%v.value)
					sensitive  = false
				}
			`, tt.name, staticPath, tt.name)

			testStaticSecretDataSource(t, config, tt.expect)
		})
	}
}

func testStaticSecretDataSource(t *testing.T, config string, expect map[string]interface{}) {
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
				// Get inner state fields
				innerStateValue := s.Modules[0].Resources["data.akeyless_static_secret.Password"].Primary.Attributes["username"]
				if val != innerStateValue {
					return fmt.Errorf("username is not equal\nexpect: %v\nactual: %v", val, innerStateValue)
				}
				value, err := convertToMapStringAny(secretDetails.Value)
				if err != nil {
					return fmt.Errorf("wrong value variable type")
				}
				username, ok := value["username"].(string)
				if !ok {
					return fmt.Errorf("wrong username variable type")
				}
				if val != username {
					return fmt.Errorf("username is not equal\nexpect: %v\nactual: %v", val, username)
				}
			case "password":
				// Get inner state fields
				innerStateValue := s.Modules[0].Resources["data.akeyless_static_secret.Password"].Primary.Attributes["password"]
				if val != innerStateValue {
					return fmt.Errorf("password is not equal\nexpect: %v\nactual: %v", val, innerStateValue)
				}
				value, err := convertToMapStringAny(secretDetails.Value)
				if err != nil {
					return fmt.Errorf("wrong value variable type")
				}
				password, ok := value["password"].(string)
				if !ok {
					return fmt.Errorf("wrong password variable type")
				}
				if val != password {
					return fmt.Errorf("password is not equal\nexpect: %v\nactual: %v", val, password)
				}
			case "custom_field":
				// Get inner state fields
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
						// Remove the prefix custom_field. from the key
						key := strings.TrimPrefix(k, "custom_field.")
						if key == "%" {
							continue // Skip the custom_field.% key
						}
						// Check if the key exists in the expected map
						expectedValue, exists := val.(map[string]interface{})[key]
						if !exists {
							return fmt.Errorf("custom field %s not found in expected value", key)
						}
						if v != expectedValue {
							return fmt.Errorf("value for custom field %s is not equal\nexpect: %v\nactual: %v", key, expectedValue, v)
						}
					}
				}
			case "inject_url":
				// Get inner state fields
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
					// Get the inject_url value for the index i
					injectUrlKey := fmt.Sprintf("inject_url.%d", i)
					injectUrlValue, ok := att[injectUrlKey]
					if !ok {
						return fmt.Errorf("inject_url.%d not found in attributes", i)
					}
					// Check if the value exists in the expected list
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
