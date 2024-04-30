package akeyless

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	cert := generateCert(t)

	privateKey := generateKey(1024)

	expect := map[string]interface{}{
		"timeout":         "1m",
		"api_key":         "aaaa",
		"api_secret":      "1234",
		"mutual_tls_cert": cert,
		"mutual_tls_key":  privateKey,
	}

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

func TestTargetDataSourceLinkedTarget(t *testing.T) {

	t.Skip("fail due to unmarshal error with Target.target.attributes")

	parentTargetName := "target-db-for-linked-target"
	parentTargetPath := testPath(parentTargetName)
	createTarget(t, parentTargetPath)
	defer deleteTarget(t, parentTargetPath)

	targetName := "target-linked-target"
	targetPath := testPath(targetName)
	targetDetailsType := "linked_target_details"

	expect := map[string]interface{}{
		"hosts":  "server1.com;my-server01,server2.com;my-server02",
		"parent": parentTargetPath,
	}

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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
		"url":                 "https://www.test.com",
		"privileged_user":     "Administrator",
		"user_password":       "1234",
		"administrative_port": "9999",
		"authorization_port":  "9031",
	}

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	cert := generateCert(t)

	expect := map[string]interface{}{
		"username":    "Administrator",
		"password":    "1234",
		"hostname":    "my.windows.server.com",
		"port":        "5986",
		"domain":      "test.com",
		"certificate": cert,
		"use_tls":     true,
	}

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

	deleteTarget(t, targetPath)

	expect := map[string]interface{}{
		"api_key":          "api_key1",
		"imap_username":    "user1",
		"imap_password":    "1234",
		"imap_fqdn":        "fqdn1",
		"imap_port":        "1234",
		"validation_email": "k@k.io",
		"timeout":          "1m",
	}

	createTargetByType(t, targetPath, targetDetailsType, expect)
	defer deleteTarget(t, targetPath)

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

type createTargetFunc func(t *testing.T, name string, details map[string]interface{})

var createTargetByTypeMap = map[string]createTargetFunc{

	"artifactory_target_details":      createArtifactoryTarget,
	"aws_target_details":              createAwsTarget,
	"azure_target_details":            createAzureTarget,
	"db_target_details":               createDbTarget,
	"dockerhub_target_details":        createDockerHubTarget,
	"eks_target_details":              createEksTarget,
	"gcp_target_details":              createGcpTarget,
	"github_target_details":           createGithubTarget,
	"gke_target_details":              createGkeTarget,
	"globalsign_atlas_target_details": createGlobalSignAtlasTarget,
	"globalsign_target_details":       createGlobalSignTarget,
	"ldap_target_details":             createLdapTarget,
	"linked_target_details":           createLinkedTarget,
	"mongo_db_target_details":         createMongoDbTarget,
	"native_k8s_target_details":       createK8sTarget,
	"ping_target_details":             createPingTarget,
	"rabbit_mq_target_details":        createRabbitMqTarget,
	"salesforce_target_details":       createSalesforceTarget,
	"ssh_target_details":              createSshTarget,
	"venafi_target_details":           nil, // not supported by CLI
	"web_target_details":              createWebTarget,
	"windows_target_details":          createWindowsTarget,
	"zerossl_target_details":          createZeroSslTarget,
}

func createTargetByType(t *testing.T, name, targetType string, details map[string]interface{}) {
	createTargetByTypeMap[targetType](t, name, details)
}

func createArtifactoryTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateArtifactoryTarget{
		Name:                 name,
		Token:                &token,
		ArtifactoryAdminName: details["admin_name"].(string),
		ArtifactoryAdminPwd:  details["admin_pwd"].(string),
		BaseUrl:              details["base_url"].(string),
	}

	_, resp, err := client.CreateArtifactoryTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createAwsTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateAWSTarget{
		Name:        name,
		Token:       &token,
		AccessKeyId: details["access_key_id"].(string),
		AccessKey:   details["access_key"].(string),
	}
	common.GetAkeylessPtr(&body.Token, details["session_token"])
	common.GetAkeylessPtr(&body.Region, details["region"])
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, details["use_gw_cloud_identity"])

	_, resp, err := client.CreateAWSTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createAzureTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateAzureTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ClientId, details["client_id"])
	common.GetAkeylessPtr(&body.TenantId, details["tenant_id"])
	common.GetAkeylessPtr(&body.ClientSecret, details["client_secret"])
	common.GetAkeylessPtr(&body.SubscriptionId, details["subscription_id"])
	common.GetAkeylessPtr(&body.ResourceGroupName, details["resource_group_name"])
	common.GetAkeylessPtr(&body.ResourceName, details["resource_name"])
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, details["use_gw_cloud_identity"])

	_, resp, err := client.CreateAzureTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createDbTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateDBTarget{
		Name:   name,
		Token:  &token,
		DbType: "mysql",
	}
	common.GetAkeylessPtr(&body.UserName, details["user_name"])
	common.GetAkeylessPtr(&body.Pwd, details["pwd"])
	common.GetAkeylessPtr(&body.Host, details["host"])
	common.GetAkeylessPtr(&body.Port, details["port"])
	common.GetAkeylessPtr(&body.DbName, details["db_name"])
	common.GetAkeylessPtr(&body.Ssl, details["ssl_connection_mode"])
	common.GetAkeylessPtr(&body.SslCertificate, details["ssl_connection_certificate"])

	_, resp, err := client.CreateDBTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createDockerHubTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateDockerhubTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DockerhubUsername, details["username"])
	common.GetAkeylessPtr(&body.DockerhubPassword, details["password"])

	_, resp, err := client.CreateDockerhubTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createEksTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateEKSTarget{
		Name:               name,
		Token:              &token,
		EksClusterName:     details["cluster_name"].(string),
		EksClusterEndpoint: details["cluster_endpoint"].(string),
		EksClusterCaCert:   details["cluster_ca_cert"].(string),
		EksAccessKeyId:     details["access_key_id"].(string),
		EksSecretAccessKey: details["access_key"].(string),
	}
	common.GetAkeylessPtr(&body.EksRegion, details["region"])

	_, resp, err := client.CreateEKSTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createGcpTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateGcpTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GcpKey, details["gcp_service_account_key"])

	_, resp, err := client.CreateGcpTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createGithubTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateGithubTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GithubAppId, details["app_id"].(int))
	common.GetAkeylessPtr(&body.GithubAppPrivateKey, details["app_private_key"])
	common.GetAkeylessPtr(&body.GithubBaseUrl, details["base_url"])

	_, resp, err := client.CreateGithubTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createGkeTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateGKETarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GkeServiceAccountEmail, details["service_account_email"])
	common.GetAkeylessPtr(&body.GkeClusterEndpoint, details["cluster_endpoint"])
	common.GetAkeylessPtr(&body.GkeClusterCert, details["cluster_ca_cert"])
	common.GetAkeylessPtr(&body.GkeAccountKey, details["service_account_key"])
	common.GetAkeylessPtr(&body.GkeClusterName, details["cluster_name"])

	_, resp, err := client.CreateGKETarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createGlobalSignAtlasTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateGlobalSignAtlasTarget{
		Name:      name,
		Token:     &token,
		ApiKey:    details["api_key"].(string),
		ApiSecret: details["api_secret"].(string),
	}
	common.GetAkeylessPtr(&body.MtlsCertDataBase64, details["mutual_tls_cert"])
	common.GetAkeylessPtr(&body.MtlsKeyDataBase64, details["mutual_tls_key"])
	common.GetAkeylessPtr(&body.Timeout, details["timeout"])

	_, resp, err := client.CreateGlobalSignAtlasTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createGlobalSignTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateGlobalSignTarget{
		Name:             name,
		Token:            &token,
		Username:         details["username"].(string),
		Password:         details["password"].(string),
		ProfileId:        details["profile_id"].(string),
		ContactFirstName: details["contact_first_name"].(string),
		ContactLastName:  details["contact_last_name"].(string),
		ContactPhone:     details["contact_phone"].(string),
		ContactEmail:     details["contact_email"].(string),
	}
	common.GetAkeylessPtr(&body.Timeout, details["timeout"])

	_, resp, err := client.CreateGlobalSignTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createLdapTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateLdapTarget{
		Name:           name,
		Token:          &token,
		LdapUrl:        details["url"].(string),
		BindDn:         details["bind_dn"].(string),
		BindDnPassword: details["bind_password"].(string),
	}
	common.GetAkeylessPtr(&body.TokenExpiration, details["token_expiration_in_sec"])
	common.GetAkeylessPtr(&body.LdapCaCert, details["certificate"])
	common.GetAkeylessPtr(&body.ServerType, details["implementation_type"])

	_, resp, err := client.CreateldapTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createLinkedTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateLinkedTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Hosts, details["hosts"])
	common.GetAkeylessPtr(&body.ParentTargetName, details["parent"])

	_, resp, err := client.CreateLinkedTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createK8sTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateNativeK8STarget{
		Name:               name,
		Token:              &token,
		K8sClusterEndpoint: details["cluster_endpoint"].(string),
		K8sClusterCaCert:   details["cluster_ca_cert"].(string),
		K8sClusterToken:    details["bearer_token"].(string),
	}

	_, resp, err := client.CreateNativeK8STarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createMongoDbTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	hostAndPort := strings.Split(details["host_port"].(string), ":")
	host := hostAndPort[0]
	port := hostAndPort[1]

	body := akeyless.CreateDBTarget{
		Name:   name,
		Token:  &token,
		DbType: "mongodb",
	}
	common.GetAkeylessPtr(&body.UserName, details["username"])
	common.GetAkeylessPtr(&body.Pwd, details["password"])
	common.GetAkeylessPtr(&body.DbName, details["db_name"])
	common.GetAkeylessPtr(&body.MongodbUriOptions, details["uri_options"])
	common.GetAkeylessPtr(&body.MongodbDefaultAuthDb, details["default_auth_db"])
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.Port, port)

	_, resp, err := client.CreateDBTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createPingTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreatePingTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.PingUrl, details["url"])
	common.GetAkeylessPtr(&body.PrivilegedUser, details["privileged_user"])
	common.GetAkeylessPtr(&body.Password, details["user_password"])
	common.GetAkeylessPtr(&body.AdministrativePort, details["administrative_port"])
	common.GetAkeylessPtr(&body.AuthorizationPort, details["authorization_port"])

	_, resp, err := client.CreatePingTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createRabbitMqTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateRabbitMQTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.RabbitmqServerUser, details["server_user"])
	common.GetAkeylessPtr(&body.RabbitmqServerPassword, details["server_password"])
	common.GetAkeylessPtr(&body.RabbitmqServerUri, details["server_uri"])

	_, resp, err := client.CreateRabbitMQTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createSalesforceTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateSalesforceTarget{
		Name:      name,
		Token:     &token,
		AuthFlow:  details["auth_flow"].(string),
		Email:     details["username"].(string),
		TenantUrl: details["tenant_url"].(string),
		ClientId:  details["client_id"].(string),
	}
	common.GetAkeylessPtr(&body.Password, details["password"])
	common.GetAkeylessPtr(&body.ClientSecret, details["client_secret"])
	common.GetAkeylessPtr(&body.SecurityToken, details["security_token"])

	_, resp, err := client.CreateSalesforceTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createSshTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateSSHTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.SshUsername, details["username"])
	common.GetAkeylessPtr(&body.SshPassword, details["password"])
	common.GetAkeylessPtr(&body.Host, details["host"])
	common.GetAkeylessPtr(&body.Port, details["port"])
	common.GetAkeylessPtr(&body.PrivateKey, details["private_key"])
	common.GetAkeylessPtr(&body.PrivateKeyPassword, details["private_key_password"])

	_, resp, err := client.CreateSSHTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createWebTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateWebTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Url, details["url"])

	_, resp, err := client.CreateWebTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createWindowsTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateWindowsTarget{
		Name:     name,
		Token:    &token,
		Username: details["username"].(string),
		Password: details["password"].(string),
		Hostname: details["hostname"].(string),
	}
	common.GetAkeylessPtr(&body.Port, details["port"])
	common.GetAkeylessPtr(&body.Domain, details["domain"])
	common.GetAkeylessPtr(&body.Certificate, details["certificate"])
	common.GetAkeylessPtr(&body.UseTls, details["use_tls"])

	_, resp, err := client.CreateWindowsTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createZeroSslTarget(t *testing.T, name string, details map[string]interface{}) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateZeroSSLTarget{
		Name:         name,
		Token:        &token,
		ApiKey:       details["api_key"].(string),
		ImapUsername: details["imap_username"].(string),
		ImapPassword: details["imap_password"].(string),
		ImapFqdn:     details["imap_fqdn"].(string),
	}
	common.GetAkeylessPtr(&body.ImapPort, details["imap_port"])
	common.GetAkeylessPtr(&body.ImapTargetEmail, details["validation_email"])
	common.GetAkeylessPtr(&body.Timeout, details["timeout"])

	_, resp, err := client.CreateZeroSSLTarget(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(resp, err))
}

func createTarget(t *testing.T, targetName string) {

	targetPath := testPath(targetName)

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	body := akeyless.CreateDBTarget{
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
	require.NoError(t, handleError(resp, err))
}
