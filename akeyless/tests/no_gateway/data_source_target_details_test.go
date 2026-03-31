package no_gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"
)

func TestTargetDataSourceArtifactory(t *testing.T) {
	targetName := "target-artifactory"
	targetPath := testPath(targetName)
	targetDetailsType := "artifactory_target_details"

	expect := map[string]interface{}{
		"base_url":   "http://www.test.com",
		"admin_name": "admin1",
		"admin_pwd":  "1234",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceAws(t *testing.T) {
	targetName := "target-aws"
	targetPath := testPath(targetName)
	targetDetailsType := "aws_target_details"

	expect := map[string]interface{}{
		"access_key_id":         "aaaa",
		"access_key":            "bbbb",
		"region":                "il-central-1",
		"use_gw_cloud_identity": true,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceAzure(t *testing.T) {
	targetName := "target-azure"
	targetPath := testPath(targetName)
	targetDetailsType := "azure_target_details"

	expect := map[string]interface{}{
		"client_id":           "aaaa",
		"tenant_id":           "bbbb",
		"client_secret":       "cccc",
		"subscription_id":     "dddd",
		"resource_group_name": "eeee",
		"resource_name":       "",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceDB(t *testing.T) {
	targetName := "target-db"
	targetPath := testPath(targetName)
	targetDetailsType := "db_target_details"

	expect := map[string]interface{}{
		"user_name":                  "user1",
		"pwd":                        "1234",
		"host":                       "127.0.0.1",
		"port":                       "5678",
		"db_name":                    "abcd",
		"ssl_connection_mode":        true,
		"ssl_connection_certificate": "YmxhYmxh",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceDockerhub(t *testing.T) {
	targetName := "target-dockerhub"
	targetPath := testPath(targetName)
	targetDetailsType := "dockerhub_target_details"

	expect := map[string]interface{}{
		"username": "user1",
		"password": "1234",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceEks(t *testing.T) {
	targetName := "target-eks"
	targetPath := testPath(targetName)
	targetDetailsType := "eks_target_details"

	expect := map[string]interface{}{
		"cluster_name":     "aaaa",
		"cluster_endpoint": "https://www.test.com",
		"cluster_ca_cert":  "YmxhYmxh",
		"access_key_id":    "bbbb",
		"access_key":       "cccc",
		"region":           "il-central-1",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceGcp(t *testing.T) {
	targetName := "target-gcp"
	targetPath := testPath(targetName)
	targetDetailsType := "gcp_target_details"

	expect := map[string]interface{}{
		"gcp_service_account_key":        "blabla",
		"gcp_service_account_key_base64": "YmxhYmxh",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceGithub(t *testing.T) {
	targetName := "target-github"
	targetPath := testPath(targetName)
	targetDetailsType := "github_target_details"

	expect := map[string]interface{}{
		"app_id":          1234,
		"app_private_key": "YmxhYmxh",
		"base_url":        "http://www.test.com",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceGke(t *testing.T) {
	targetName := "target-gke"
	targetPath := testPath(targetName)
	targetDetailsType := "gke_target_details"

	expect := map[string]interface{}{
		"service_account_email": "k@k.io",
		"cluster_endpoint":      "https://www.test.com",
		"cluster_ca_cert":       "YmxhYmxh",
		"service_account_key":   "aaaa",
		"cluster_name":          "bbbb",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceGlobalSignAtlas(t *testing.T) {
	targetName := "target-globalsign-atlas"
	targetPath := testPath(targetName)
	targetDetailsType := "globalsign_atlas_target_details"

	cert := testutils.GenerateCert(t)

	privateKey := testutils.GenerateKey(1024)

	expect := map[string]interface{}{
		"timeout":         "1m",
		"api_key":         "aaaa",
		"api_secret":      "1234",
		"mutual_tls_cert": cert,
		"mutual_tls_key":  privateKey,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceGlobalSign(t *testing.T) {
	targetName := "target-globalsign"
	targetPath := testPath(targetName)
	targetDetailsType := "globalsign_target_details"

	expect := map[string]interface{}{
		"timeout":            "1m",
		"username":           "user1",
		"password":           "1234",
		"profile_id":         "id1",
		"contact_first_name": "first1",
		"contact_last_name":  "last1",
		"contact_phone":      "phone1",
		"contact_email":      "k@k.io",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceLdap(t *testing.T) {
	targetName := "target-ldap"
	targetPath := testPath(targetName)
	targetDetailsType := "ldap_target_details"

	expect := map[string]interface{}{
		"url":                     "https://www.test.com",
		"bind_dn":                 "bind_dn1",
		"bind_password":           "1234",
		"token_expiration_in_sec": "42",
		"certificate":             "YmxhYmxh",
		"implementation_type":     "OpenLDAP",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceK8s(t *testing.T) {
	targetName := "target-k8s"
	targetPath := testPath(targetName)
	targetDetailsType := "native_k8s_target_details"

	expect := map[string]interface{}{
		"cluster_endpoint": "https://www.test.com",
		"cluster_ca_cert":  "YmxhYmxh",
		"bearer_token":     "Ymxh",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceMongoDb(t *testing.T) {
	targetName := "target-mongodb"
	targetPath := testPath(targetName)
	targetDetailsType := "mongo_db_target_details"

	expect := map[string]interface{}{
		"db_name":         "aaaa",
		"username":        "bbbb",
		"password":        "1234",
		"host_port":       "127.0.0.1:1234",
		"default_auth_db": "admin",
		"uri_options":     "cccc",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourcePing(t *testing.T) {
	targetName := "target-ping"
	targetPath := testPath(targetName)
	targetDetailsType := "ping_target_details"

	expect := map[string]interface{}{
		"url":                 "https://console.akeyless.io",
		"privileged_user":     "Administrator",
		"user_password":       "1234",
		"administrative_port": "9999",
		"authorization_port":  "9031",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceRabbitMQ(t *testing.T) {
	targetName := "target-rabbitmq"
	targetPath := testPath(targetName)
	targetDetailsType := "rabbit_mq_target_details"

	expect := map[string]interface{}{
		"server_user":     "aaaa",
		"server_password": "1234",
		"server_uri":      "http://127.0.0.1:15672",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceSalesforce(t *testing.T) {
	targetName := "target-salesforce"
	targetPath := testPath(targetName)
	targetDetailsType := "salesforce_target_details"

	expect := map[string]interface{}{
		"auth_flow":      "USER-PASSWORD",
		"username":       "aaaa",
		"password":       "1234",
		"tenant_url":     "http://www.test.com",
		"client_id":      "bbbb",
		"client_secret":  "cccc",
		"security_token": "YmxhYmxh",
		"ca_cert_name":   "",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceSSH(t *testing.T) {
	targetName := "target-ssh"
	targetPath := testPath(targetName)
	targetDetailsType := "ssh_target_details"

	expect := map[string]interface{}{
		"username":             "user1",
		"password":             "1234",
		"host":                 "127.0.0.1",
		"port":                 "22",
		"private_key_password": "9090",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceWeb(t *testing.T) {
	targetName := "target-web"
	targetPath := testPath(targetName)
	targetDetailsType := "web_target_details"

	expect := map[string]interface{}{
		"url": "https://www.test.com",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceWindows(t *testing.T) {
	targetName := "target-windows"
	targetPath := testPath(targetName)
	targetDetailsType := "windows_target_details"

	cert := testutils.GenerateCert(t)

	expect := map[string]interface{}{
		"username":    "Administrator",
		"password":    "1234",
		"hostname":    "my.windows.server.com",
		"port":        "5986",
		"domain":      "test.com",
		"certificate": cert,
		"use_tls":     true,
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func TestTargetDataSourceZeroSsl(t *testing.T) {
	targetName := "target-zerossl"
	targetPath := testPath(targetName)
	targetDetailsType := "zerossl_target_details"

	testutils.DeleteTarget(t, targetPath)

	expect := map[string]interface{}{
		"api_key":          "api_key1",
		"imap_username":    "user1",
		"imap_password":    "1234",
		"imap_fqdn":        "fqdn1",
		"imap_port":        "1234",
		"validation_email": "k@k.io",
		"timeout":          "1m",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func testTargetDataSource(t *testing.T, config, targetPath, targetType string, expect map[string]interface{}) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkTargetDetailsRemotely(targetPath, targetType, expect),
				),
			},
		},
	})
}

func checkTargetDetailsRemotely(path, targetType string, expect map[string]interface{}) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		targetDetails := s.Modules[0].Outputs["target_details"]
		if targetDetails == nil {
			return fmt.Errorf("target details not shown in terraform output")
		}

		value, ok := targetDetails.Value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("wrong value variable type")

		}

		valuePerType, ok := value[targetType]
		if !ok {
			return fmt.Errorf("wrong value target type")
		}

		details, ok := valuePerType.(string)
		if !ok {
			return fmt.Errorf("wrong details variable type")
		}

		var detailsMap map[string]interface{}
		err := json.Unmarshal([]byte(details), &detailsMap)
		if err != nil {
			return err
		}

		adjustResultAndInput(detailsMap, expect, targetType)

		eq := reflect.DeepEqual(detailsMap, expect)
		if !eq {
			return fmt.Errorf("value is not equal\nexpect: %v\nactual: %v", expect, value)
		}

		return nil
	}
}

func adjustResultAndInput(actual, expect map[string]interface{}, targetType string) error {
	// app_id represented as float64 but it is int (TF issue)
	if val, ok := actual["app_id"]; ok {
		if fVal, ok := val.(float64); ok {
			actual["app_id"] = int(fVal)
		}
	}

	// timeout is time.Duration in input (1m) and nanoseconds in output (6e+10)
	if val, ok := expect["timeout"]; ok {
		dur, err := time.ParseDuration(val.(string))
		if err != nil {
			return err
		}
		expect["timeout"] = int(dur)
	}
	if val, ok := actual["timeout"]; ok {
		if fVal, ok := val.(float64); ok {
			actual["timeout"] = int(fVal)
		}
	}

	// ldap & windows result is not aligned with the input (base64 vs no base64)
	if val, ok := actual["certificate"]; ok {
		if fVal, ok := val.(string); ok {
			actual["certificate"] = base64.RawStdEncoding.EncodeToString([]byte(fVal))

			// windows output comes without "=" suffix
			if targetType == "windows_target_details" {
				if !strings.HasSuffix(actual["certificate"].(string), "=") {
					actual["certificate"] = actual["certificate"].(string) + "="
				}
			}
		}
	}

	return nil
}

func createTarget(t *testing.T, targetName string) {

	targetPath := testPath(targetName)

	client, token, err := testutils.GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateDBTarget{
		Name:   targetPath,
		Token:  &token,
		DbType: "mysql",
	}
	common.GetAkeylessPtr(&body.UserName, "user1")
	common.GetAkeylessPtr(&body.Pwd, "1234")
	common.GetAkeylessPtr(&body.Host, "127.0.0.1")
	common.GetAkeylessPtr(&body.Port, "5678")
	common.GetAkeylessPtr(&body.DbName, "abcd")

	_, resp, err := client.CreateDBTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create db target for test", resp, err))
}
