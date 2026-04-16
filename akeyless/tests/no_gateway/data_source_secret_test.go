package no_gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

type testSecretType string

const (
	staticSecretType testSecretType = "STATIC_SECRET"

	staticSecretValueForTest string = "1234"
)

func TestSecretDataSource(t *testing.T) {
	t.Run("static", testSecretDataSourceStatic)
}

func testSecretDataSourceStatic(t *testing.T) {
	secretName := "test_secret"
	secretPath := testPath(secretName)

	secret := &testutils.TestSecret{
		SecretName: secretPath,
		Value:      staticSecretValueForTest,
	}
	testutils.CreateSecret(t, secret)
	defer testutils.DeleteItemIfExists(t, secretPath)

	config := fmt.Sprintf(`
		data "akeyless_secret" "%v" {
			path = "%v"
		}
		output "secret" {
			value      = nonsensitive(data.akeyless_secret.%v.value)
			sensitive  = false
		}
	`, secretName, secretPath, secretName)

	testSecretDataSource(t, config, staticSecretType, staticSecretValueForTest)
}

func testSecretDataSource(t *testing.T, config string, secretType testSecretType, expectStatic string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkSecretExpectedStash(secretType, expectStatic),
				),
			},
		},
	})
}

func checkSecretExpectedStash(secretType testSecretType, expectStatic string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		switch secretType {
		case staticSecretType:
			secretDetails := s.Modules[0].Outputs["secret"]
			if secretDetails == nil {
				return fmt.Errorf("target details not shown in terraform output")
			}
			value, ok := secretDetails.Value.(string)
			if !ok {
				return fmt.Errorf("wrong value variable type")
			}
			if expectStatic != value {
				return fmt.Errorf("value is not equal\nexpect: %v\nactual: %v", expectStatic, value)
			}
		default:
			secretDetails := s.Modules[0].Outputs["secret"]
			if secretDetails == nil {
				return fmt.Errorf("target details not shown in terraform output")
			}
			if secretDetails.Value == nil {
				return fmt.Errorf("secret value is nil")
			}
			value, ok := secretDetails.Value.(string)
			if !ok {
				return fmt.Errorf("wrong value variable type")
			}
			if !strings.Contains(value, "user") || !strings.Contains(value, "password") {
				return fmt.Errorf("dynamic secret value for mysql host not contains user or password")
			}
		}
		return nil
	}
}
