package akeyless

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestGatewayUpdateLogForwardingAwsS3(t *testing.T) {
	skipIfNoGateway(t)

	name := "test-gw-log-forwarding-aws-s3"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_aws_s3" "%v" {
 			enable        	= "false"
			output_format 	= "json"
			pull_interval   = "20"
			log_folder 		= "folder1"
			bucket_name 	= "bucket1"
			auth_type 		= "access_key"
			access_id 		= "id1"
			access_key 		= "key1"
			region 			= "us-east-2"
		}
	`, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_aws_s3" "%v" {
 			enable        	= "false"
			output_format 	= "text"
			pull_interval   = "10"
			log_folder 		= "folder2"
			bucket_name 	= "bucket2"
			auth_type 		= "access_key"
			access_id 		= "id2"
			access_key 		= "key2"
			region 			= "eu-west-1"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingAzureAnalytics(t *testing.T) {
	skipIfNoGateway(t)

	name := "test-gw-log-forwarding-azure-analytics"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_azure_analytics" "%v" {
 			enable        	= "false"
			output_format 	= "json"
			pull_interval   = "20"
			workspace_id 	= "id1"
			workspace_key 	= "key1"
		}
	`, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_azure_analytics" "%v" {
 			enable        	= "false"
			output_format 	= "text"
			pull_interval   = "10"
			workspace_id 	= "id2"
			workspace_key 	= "key2"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingDatadog(t *testing.T) {
	skipIfNoGateway(t)

	name := "test-gw-log-forwarding-datadog"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_datadog" "%v" {
 			enable        	= "false"
			output_format 	= "json"
			pull_interval   = "20"
			host 			= "datadoghq.com"
			api_key 		= "key1"
			log_source 		= "akeyless"
			log_tags 		= "env:test,version:1"
			log_service 	= "test"
		}
	`, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_datadog" "%v" {
 			enable        	= "false"
			output_format 	= "text"
			pull_interval   = "10"
			host 			= "datadoghq.com"
			api_key 		= "key2"
			log_source 		= "akeyless-updated"
			log_tags 		= "env:prod"
			log_service 	= "prod"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingElasticsearch(t *testing.T) {
	skipIfNoGateway(t)

	_, cert := generateCertForTest(t, 1024)
	name := "test-gw-log-forwarding-elasticsearch"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_elasticsearch" "%v" {
 			enable        	= "false"
			output_format 	= "json"
			pull_interval   = "20"
			index 			= "akeylesslog"
			server_type 	= "nodes"
			nodes 			= "https://localhost:9200"
			auth_type 		= "password"
			user_name 		= "elastic"
			password 		= "12345678"
			enable_tls 		= true
			tls_certificate	= "%v"
		}
	`, name, cert)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_elasticsearch" "%v" {
 			enable        	= "false"
			output_format 	= "text"
			pull_interval   = "10"
			index 			= "akeylesslog2"
			server_type 	= "nodes"
			nodes 			= "https://localhost:9201"
			auth_type 		= "password"
			user_name 		= "admin"
			password 		= "newpass"
			enable_tls 		= true
			tls_certificate	= "%v"
		}
	`, name, cert)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingGoogleChronicle(t *testing.T) {
	skipIfNoGateway(t)

	name := "test-gw-log-forwarding-google-chronicle"

	dummyJsonKey := `{
		"private_key_id": "1234",
		"private_key": "super-secret-key",
		"client_email": "gopher@developer.gserviceaccount.com",
		"client_id": "gopher.apps.googleusercontent.com",
		"token_uri": "some-token-uri",
		"type": "service_account",
		"audience": "https://testservice.googleapis.com/"
	}`
	saKey := common.Base64Encode(dummyJsonKey)
	customerID := uuid.NewString()

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_google_chronicle" "%v" {
 			enable        	= "false"
			output_format 	= "json"
			pull_interval   = "20"
			gcp_key 		= "%s"
			customer_id 	= "%s"
			region 			= "eu_multi_region"
			log_type 		= "test"
		}
	`, name, saKey, customerID)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_google_chronicle" "%v" {
 			enable        	= "false"
			output_format 	= "text"
			pull_interval   = "10"
			gcp_key 		= "%s"
			customer_id 	= "%s"
			region 			= "us_multi_region"
			log_type 		= "prod"
		}
	`, name, saKey, customerID)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingLogstash(t *testing.T) {
	skipIfNoGateway(t)

	_, cert := generateCertForTest(t, 1024)
	name := "test-gw-log-forwarding-logstash"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_logstash" "%v" {
 			enable        	= "false"
			output_format 	= "json"
			pull_interval   = "20"
			dns 			= "127.0.0.1:8080"
			protocol 		= "tcp"
			enable_tls 		= true
			tls_certificate	= "%v"
		}
	`, name, cert)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_logstash" "%v" {
 			enable        	= "false"
			output_format 	= "text"
			pull_interval   = "10"
			dns 			= "127.0.0.1:9090"
			protocol 		= "tcp"
			enable_tls 		= true
			tls_certificate	= "%v"
		}
	`, name, cert)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingLogzIo(t *testing.T) {
	skipIfNoGateway(t)

	name := "test-gw-log-forwarding-logz-io"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_logz_io" "%v" {
 			enable        	= "false"
			output_format 	= "json"
			pull_interval   = "20"
			logz_io_token 	= "abcd"
			protocol 		= "tcp"
		}
	`, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_logz_io" "%v" {
 			enable        	= "false"
			output_format 	= "text"
			pull_interval   = "10"
			logz_io_token 	= "efgh"
			protocol 		= "tcp"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingSplunk(t *testing.T) {
	skipIfNoGateway(t)

	_, cert := generateCertForTest(t, 1024)
	name := "test-gw-log-forwarding-splunk"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_splunk" "%v" {
 			enable        	= "false"
			output_format 	= "json"
			pull_interval   = "20"
			splunk_url 		= "127.0.0.1:8080"
			splunk_token 	= "abcd"
			source 			= "/tmp/source1"
			source_type 	= "type1"
			index 			= "index1"
			enable_tls 		= true
			tls_certificate	= "%v"
		}
	`, name, cert)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_splunk" "%v" {
 			enable        	= "false"
			output_format 	= "text"
			pull_interval   = "10"
			splunk_url 		= "127.0.0.1:9090"
			splunk_token 	= "efgh"
			source 			= "/tmp/source2"
			source_type 	= "type2"
			index 			= "index2"
			enable_tls 		= true
			tls_certificate	= "%v"
		}
	`, name, cert)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingStdout(t *testing.T) {
	skipIfNoGateway(t)

	name := "test-gw-log-forwarding-stdout"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_stdout" "%v" {
 			enable        	= "true"
			output_format 	= "json"
			pull_interval   = "20"
		}
	`, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_stdout" "%v" {
 			enable        	= "true"
			output_format 	= "text"
			pull_interval   = "10"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingSumologic(t *testing.T) {
	skipIfNoGateway(t)

	name := "test-gw-log-forwarding-sumologic"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_sumologic" "%v" {
 			enable        	= "false"
			output_format 	= "json"
			pull_interval   = "20"
			endpoint 		= "https://endpoint.collection.sumologic.com/receiver/v1/http/key"
			sumologic_tags 	= "tag1,tag2,tag3"
			host 			= "sumologichost.com"
		}
	`, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_sumologic" "%v" {
 			enable        	= "false"
			output_format 	= "text"
			pull_interval   = "10"
			endpoint 		= "https://endpoint.collection.sumologic.com/receiver/v1/http/key2"
			sumologic_tags 	= "tag4,tag5"
			host 			= "sumologichost2.com"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingSyslog(t *testing.T) {
	skipIfNoGateway(t)

	_, cert := generateCertForTest(t, 1024)
	name := "test-gw-log-forwarding-syslog"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_syslog" "%v" {
 			enable        	= "false"
			output_format 	= "json"
			pull_interval   = "20"
			network 		= "tcp"
			host 			= "127.0.0.1:8080"
			target_tag 		= "tag1"
			formatter 		= "cef"
			enable_tls 		= true
			tls_certificate	= "%v"
		}
	`, name, cert)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_syslog" "%v" {
 			enable        	= "false"
			output_format 	= "text"
			pull_interval   = "10"
			network 		= "udp"
			host 			= "127.0.0.1:514"
			target_tag 		= "tag2"
			formatter 		= "text"
			enable_tls 		= false
			tls_certificate	= "use-existing"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func testGatewayConfigResource(t *testing.T, config, configUpdate string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
			},
			{
				Config: configUpdate,
			},
		},
	})
}
