package akeyless

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// When enabling the tests, the certificate should be returned from an elastic docker instance. It isn't a secret.
const ElasticCertForTest string = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURTakNDQWpLZ0F3SUJBZ0lWQU9RMGZzQUJLbUZleFdqVG5sT1BZZVc0alJOMU1BMEdDU3FHU0liM0RRRUIKQ3dVQU1EUXhNakF3QmdOVkJBTVRLVVZzWVhOMGFXTWdRMlZ5ZEdsbWFXTmhkR1VnVkc5dmJDQkJkWFJ2WjJWdQpaWEpoZEdWa0lFTkJNQjRYRFRJME1EUXdNVEUwTXpFeU0xb1hEVEkzTURRd01URTBNekV5TTFvd05ERXlNREFHCkExVUVBeE1wUld4aGMzUnBZeUJEWlhKMGFXWnBZMkYwWlNCVWIyOXNJRUYxZEc5blpXNWxjbUYwWldRZ1EwRXcKZ2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQzZoMVBIN1hkMHpyaGk4MllwTy9IQwpWeDY4amlBK0w1V3pHYWJrNXl3Q3lqKzFERExPSHBKREVXOFpRSVdMa3RZMFBhRlF2Z041NDk5MDVQL0pjS3BQCmFHNnlZbGdNd29IckJzOWQvK2ZrMGpHL29ueU5GY25hR3BBWHVHNS91UWsyeU02TGdHZVp6c20wdzcrTWhzaEUKcHUrNzUvMlhPUTE3ejRSTmRlZ3BGSjl0SUlQVHI2dHRpR2E1bVpDaWdNbVluQm1pWXRzZG9TbzdvSDQ4eXVTeApCYnhaVFl3QVBCR0svWWRGVkYrekJwaW56YU5wNGd4Z3FYV2tIbUlHUXZUQ2hqQ1ZIYldSKzhnSm5VUHB5NmF3Cm93d1F5ZnhDOFZzNjREeXpDWlBiQVJ3eGZvYTVSeWRlN2pLZDJHSGhaaWg2VndhdGpLaE92MlpZOGp0dUxPdngKQWdNQkFBR2pVekJSTUIwR0ExVWREZ1FXQkJRcHA5VVlVeVhqcC9XSTQySEJpeHc1OVpiNnN6QWZCZ05WSFNNRQpHREFXZ0JRcHA5VVlVeVhqcC9XSTQySEJpeHc1OVpiNnN6QVBCZ05WSFJNQkFmOEVCVEFEQVFIL01BMEdDU3FHClNJYjNEUUVCQ3dVQUE0SUJBUUJVaXMyMzF6SzVrR2VoZjVjalZna2psdVNQRi9yNDArRlh4L3BVMFNjaTc1U3MKVUxkemRYRnpnNjBVMENFOTdjU0VmeWVzQWJUUjBNY01yT0VRVkYybVo4bzVRb0FxZzdXK0ZRSVI0TnZHWVVrQQpNY0UzSm13TlJnSkNZZkt3Y1plbFZtSEp2Zy8zbS83RTZhcTY3bVVEVVRZMXVWNVIvcEdmQUh2enlFL1U1b0JECk9NRU80Wm5GUzlJVFFNOW5sZzRRcy9DcGJDbGpXbGM4MDRQT3UvTTZBb3FxYWRXeWhrT0RaaityWHIrWmV1dUUKQWxOZjdPOWR6VkRnNWtCeUltd0hnQWFzc1kyYzBRUGh2bWJhY0JsUlRZaTV1d2lST0lrcjc0Y2lENzZFdUU0ZgoyRVRUSHl5d3RrZWRSR1puOWloVkxpbmN1WDBPY1ltVW9BZUlMVHZiCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="

func TestGatewayUpdateLogForwardingAwsS3(t *testing.T) {
	t.Skip("not supported on public gateway & fictive values")
	t.Parallel()

	name := "test-gw-log-forwarding-aws-s3"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_aws_s3" "%v" {
 			enable        	= "true"
			output_format 	= "json"
			pull_interval   = "20"
			log_folder 		= "folder1"
			bucket_name 	= "bucket1"
			auth_type 		= "access_key"
			access_id 		= "id1"
			access_key 		= "key1"
			region 			= "us-east-2"
			role_arn 		= ""
		}
	`, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_aws_s3" "%v" {
			enable        	= "true"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingAzureAnalytics(t *testing.T) {
	t.Skip("not supported on public gateway & fictive values")
	t.Parallel()

	name := "test-gw-log-forwarding-azure-analytics"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_azure_analytics" "%v" {
 			enable        	= "true"
			output_format 	= "json"
			pull_interval   = "20"
			workspace_id 	= "id1"
			workspace_key 	= "key1"
		}
	`, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_azure_analytics" "%v" {
			enable        	= "true"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingDatadog(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

	name := "test-gw-log-forwarding-datadog"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_datadog" "%v" {
 			enable        	= "true"
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
			enable        	= "true"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingElasticsearch(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

	name := "test-gw-log-forwarding-elasticsearch"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_elasticsearch" "%v" {
 			enable        	= "true"
			output_format 	= "json"
			pull_interval   = "20"
			index 			= "akeylesslog"
			server_type 	= "nodes"
			nodes 			= "https://localhost:9200"
			cloud_id 		= ""
			auth_type 		= "password"
			api_key 		= ""
			user_name 		= "elastic"
			password 		= "12345678"
			enable_tls 		= true
			tls_certificate	= "%v"
		}
	`, name, ElasticCertForTest)

	// the container accepts only https request, so must enable tls
	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_elasticsearch" "%v" {
			enable        	= "true"
			enable_tls 		= true
			tls_certificate	= "%v"
		}
	`, name, ElasticCertForTest)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingGoogleChronicle(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

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
 			enable        	= "true"
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
			enable        	= "true"
			gcp_key 		= "%s"
		}
	`, name, saKey)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingLogstash(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

	_, cert := generateCertForTest(t, 1024)
	name := "test-gw-log-forwarding-logstash"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_logstash" "%v" {
 			enable        	= "true"
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
			enable        	= "true"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingLogzIo(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

	name := "test-gw-log-forwarding-logz-io"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_logz_io" "%v" {
 			enable        	= "true"
			output_format 	= "json"
			pull_interval   = "20"
			logz_io_token 	= "abcd"
			protocol 		= "tcp"
		}
	`, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_logz_io" "%v" {
			enable        	= "true"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingSplunk(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

	_, cert := generateCertForTest(t, 1024)
	name := "test-gw-log-forwarding-splunk"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_splunk" "%v" {
 			enable        	= "true"
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
			enable        	= "true"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingStdout(t *testing.T) {
	// t.Skip("not supported on public gateway")
	// t.Parallel()

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
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingSumologic(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

	name := "test-gw-log-forwarding-sumologic"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_sumologic" "%v" {
 			enable        	= "true"
			output_format 	= "json"
			pull_interval   = "20"
			endpoint 		= "https://endpoint.collection.sumologic.com/receiver/v1/http/key"
			sumologic_tags 	= "tag1,tag2,tag3"
			host 			= "sumologichost.com"
		}
	`, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_sumologic" "%v" {
			enable        	= "true"
		}
	`, name)

	testGatewayConfigResource(t, config, configUpdate)
}

func TestGatewayUpdateLogForwardingSyslog(t *testing.T) {
	t.Skip("not supported on public gateway")
	t.Parallel()

	_, cert := generateCertForTest(t, 1024)
	name := "test-gw-log-forwarding-syslog"

	config := fmt.Sprintf(`
		resource "akeyless_gateway_log_forwarding_syslog" "%v" {
 			enable        	= "true"
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
			enable        	= "true"
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
