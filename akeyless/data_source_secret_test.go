package akeyless

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

type testSecretType string

const (
	staticSecretType  testSecretType = "STATIC_SECRET"
	dynamicSecretType testSecretType = "DYNAMIC_SECRET"
	rotatedSecretType testSecretType = "ROTATED_SECRET"

	staticSecretValueForTest string = "1234"
	mysqlTestUsername        string = "root"
	mysqlTestPassword        string = "password"
	mysqlTestHost            string = "127.0.0.1"
	mysqlTestPort            string = "3306"
	mysqlTestDBName          string = "mysql"
)

func TestSecretDataSource(t *testing.T) {

	t.Run("static", testSecretDataSourceStatic)
	t.Run("dynamic", testSecretDataSourceDynamic)
	t.Run("rotated", testSecretDataSourceRotated)
}

func testSecretDataSourceStatic(t *testing.T) {

	secretName := "test_secret"
	secretPath := testPath(secretName)

	secret := &testSecret{
		secretName: secretPath,
		value:      staticSecretValueForTest,
	}
	createSecret(t, secret)
	defer deleteItemIfExists(t, secretPath)

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

func testSecretDataSourceDynamic(t *testing.T) {

	t.Skip("dynamic secret requires gateway")

	secretName := "test_secret_dynamic"
	secretPath := testPath(secretName)

	secret := &testMysqlDynamicSecret{
		secretName: secretPath,
		username:   mysqlTestUsername,
		password:   mysqlTestPassword,
		host:       mysqlTestHost,
		port:       mysqlTestPort,
		dbName:     mysqlTestDBName,
	}
	createMysqlDynamicSecret(t, secret)
	defer deleteItemIfExists(t, secretPath)

	config := fmt.Sprintf(`
		data "akeyless_secret" "%v" {
			path = "%v"
		}
		output "secret" {
			value      = nonsensitive(data.akeyless_secret.%v.value)
			sensitive  = false
		}
	`, secretName, secretPath, secretName)

	testSecretDataSource(t, config, dynamicSecretType, "")
}

func testSecretDataSourceRotated(t *testing.T) {

	t.Skip("rotated secret requires gateway")

	targetName := "test-target-db-for-rotator"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	targetDetails := map[string]any{
		"user_name": mysqlTestUsername,
		"pwd":       mysqlTestPassword,
		"host":      mysqlTestHost,
		"port":      mysqlTestPort,
		"db_name":   mysqlTestDBName,
	}

	createTargetByType(t, targetPath, targetDetailsType, targetDetails)
	defer deleteTarget(t, targetPath)

	secretName := "test_secret_rotated"
	secretPath := testPath(secretName)

	secret := &testMysqlRotatedSecret{
		secretName: secretPath,
		targetName: targetPath,
	}
	createMysqlRotatedSecret(t, secret)
	defer deleteItemIfExists(t, secretPath)

	config := fmt.Sprintf(`
		data "akeyless_secret" "%v" {
			path = "%v"
		}
		output "secret" {
			value      = nonsensitive(data.akeyless_secret.%v.value)
			sensitive  = false
		}
	`, secretName, secretPath, secretName)

	testSecretDataSource(t, config, rotatedSecretType, "")
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
		case dynamicSecretType, rotatedSecretType:
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
		default:
			return fmt.Errorf("unknown secret type")
		}

		return nil
	}
}
