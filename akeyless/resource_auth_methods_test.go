package akeyless

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const CERT_DATA = "-----BEGIN CERTIFICATE-----MIIFCTCCAvGgAwIBAgICTuowDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEChMLYWtleWxlc3MuaW8wHhcNMjIwNTA0MTExMzE0WhcNMjIwODA0MTExMzE0WjAWMRQwEgYDVQQKEwtha2V5bGVzcy5pbzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJoUUiAazKbn/MsufPXKfGdIWC3LRR1a+4FHyuzRrNZV7QtWgYlnUuVjZxfUTBD/mqTP4Tw5bKORwwPpJ6SPgowzcfj4EUaI5trWQUWDiMV6Tto6AJeRZMhZqc2HlQkccv3ryYFJSpUf8CTUTMLH/B0wJon2CNXtN/zeBrfCZ8+h8qQmP0WWkeRHzdULTwjt/zEzyve79QQefnW2kZ7xNeLke8co8siAM4gZtlKDQxCwDNu7DV4ilDZ0VaAzgsRnBLOWc1C9x5cLHsm0E/z1AYGvyzdmf/bts5+8E68xlt+/JvVbjHHIKWW1FSLB+0aJbwhYFgEMX/ebKByuQq2R/lTSIqNwN4Ygmq+NgkkGbui1u0GSp0HlHyFF7WfwgVBUv+PqLyOWofEY0vc6v5RYg6gdIozLBYxNuOfMI35/vQjHJ+v3T9ThdnH5fpoBXy8E4i/yZLx2jTZDObrLcV0BKVOZdaS+cQQNXvg1PjmoZrb7CWshVqzTrHm3yc+Wlkhq9CXE1mPGBCZEFmd/FudWqtT36DUocS8zqrbAuvBzW8F30O0zYUtuph0+g0s6UqnA2AMirKzDXmbzVROsFaaNZ8YLFR4rLjaBkl2D8oLP01RIIeC6z07PLQju9SBNF0zcBGXFYVm7ZMl53qL7X2Ovu25Aq3V5IVkdPsuaet7dEpqNAgMBAAGjYTBfMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUXy+5W+AkOsS+RjDPM1WzYiqNu+4wDQYJKoZIhvcNAQELBQADggIBABHD/7nk4WCXUTQbpSljcDTeOD7jRdcUrSqCW/uTAbownYRl15/hbqBPeWN1UiiCm/MOUiMT9tJjgkKaOqeZ3w8+BJGTkCiE/wlZeemWofHFK8j/eLkksgD1rd3lpF3hQfOlfv4KgEXtO/16a2Bc4cmfmLyCOT/QB0OxcetxTC5d0JvNAAztkIwug7l/zg4JXC/o9p5vp49SjcKh8H5NC255Ypj4ozI8ReGn1ud4vPqiRaU5zG0G4CfLRSLQcorHYFqpL/vA1p0tfzL0l3a+DKx5K678SIO0D21DTB3VPJDW4Pzz9iLGmxc8/PfjKic6D/8nf73WzJgD7szCv3UVWFkiczuTySxQsxrmfAONcSSDPImB6/4Jt90yefsJit0lpR5QFBbvZGTfa6WdzZ2/JmhuP1aWkSp1NN33PMeEBHL816zgc9j0ntSz7PjcCuUMHu/1jS6Ii3S5BvPnkV8QzWACbw7KdwH4WMtRfQ/pa8khh1BwAdt0hDN+exBpFfLTXSCCS+EeJ+oc6/wlPdq8rDiXVu3w5HLhXblB6KFk+dHErwzUizX5FxzDXwyUuWBg+Ocbh4nuIgr+GO6QRMA8IZNHB2bG5ZeWIf4/NqYa68P58m/5Ve5hQoElxWk657eyFXGmS9qFhWiMpfizl3y6+XujgZTiSvvS2IQxiqThSfNS-----END CERTIFICATE-----"
const CERT_ENCODED = "TUlJRkNUQ0NBdkdnQXdJQkFnSUNUdW93RFFZSktvWklodmNOQVFFTEJRQXdGakVVTUJJR0ExVUVDaE1MWVd0bGVXeGxjM011YVc4d0hoY05Nakl3TlRBME1URXhNekUwV2hjTk1qSXdPREEwTVRFeE16RTBXakFXTVJRd0VnWURWUVFLRXd0aGEyVjViR1Z6Y3k1cGJ6Q0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQUpvVVVpQWF6S2JuL01zdWZQWEtmR2RJV0MzTFJSMWErNEZIeXV6UnJOWlY3UXRXZ1lsblV1VmpaeGZVVEJEL21xVFA0VHc1YktPUnd3UHBKNlNQZ293emNmajRFVWFJNXRyV1FVV0RpTVY2VHRvNkFKZVJaTWhacWMySGxRa2NjdjNyeVlGSlNwVWY4Q1RVVE1MSC9CMHdKb24yQ05YdE4vemVCcmZDWjgraDhxUW1QMFdXa2VSSHpkVUxUd2p0L3pFenl2ZTc5UVFlZm5XMmtaN3hOZUxrZThjbzhzaUFNNGdadGxLRFF4Q3dETnU3RFY0aWxEWjBWYUF6Z3NSbkJMT1djMUM5eDVjTEhzbTBFL3oxQVlHdnl6ZG1mL2J0czUrOEU2OHhsdCsvSnZWYmpISElLV1cxRlNMQiswYUpid2hZRmdFTVgvZWJLQnl1UXEyUi9sVFNJcU53TjRZZ21xK05na2tHYnVpMXUwR1NwMEhsSHlGRjdXZndnVkJVditQcUx5T1dvZkVZMHZjNnY1UllnNmdkSW96TEJZeE51T2ZNSTM1L3ZRakhKK3YzVDlUaGRuSDVmcG9CWHk4RTRpL3laTHgyalRaRE9ickxjVjBCS1ZPWmRhUytjUVFOWHZnMVBqbW9acmI3Q1dzaFZxelRySG0zeWMrV2xraHE5Q1hFMW1QR0JDWkVGbWQvRnVkV3F0VDM2RFVvY1M4enFyYkF1dkJ6VzhGMzBPMHpZVXR1cGgwK2cwczZVcW5BMkFNaXJLekRYbWJ6VlJPc0ZhYU5aOFlMRlI0ckxqYUJrbDJEOG9MUDAxUklJZUM2ejA3UExRanU5U0JORjB6Y0JHWEZZVm03Wk1sNTNxTDdYMk92dTI1QXEzVjVJVmtkUHN1YWV0N2RFcHFOQWdNQkFBR2pZVEJmTUE0R0ExVWREd0VCL3dRRUF3SUNoREFkQmdOVkhTVUVGakFVQmdnckJnRUZCUWNEQWdZSUt3WUJCUVVIQXdFd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVVh5KzVXK0FrT3NTK1JqRFBNMVd6WWlxTnUrNHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnSUJBQkhELzduazRXQ1hVVFFicFNsamNEVGVPRDdqUmRjVXJTcUNXL3VUQWJvd25ZUmwxNS9oYnFCUGVXTjFVaWlDbS9NT1VpTVQ5dEpqZ2tLYU9xZVozdzgrQkpHVGtDaUUvd2xaZWVtV29mSEZLOGovZUxra3NnRDFyZDNscEYzaFFmT2xmdjRLZ0VYdE8vMTZhMkJjNGNtZm1MeUNPVC9RQjBPeGNldHhUQzVkMEp2TkFBenRrSXd1ZzdsL3pnNEpYQy9vOXA1dnA0OVNqY0toOEg1TkMyNTVZcGo0b3pJOFJlR24xdWQ0dlBxaVJhVTV6RzBHNENmTFJTTFFjb3JIWUZxcEwvdkExcDB0ZnpMMGwzYStES3g1SzY3OFNJTzBEMjFEVEIzVlBKRFc0UHp6OWlMR214YzgvUGZqS2ljNkQvOG5mNzNXekpnRDdzekN2M1VWV0ZraWN6dVR5U3hRc3hybWZBT05jU1NEUEltQjYvNEp0OTB5ZWZzSml0MGxwUjVRRkJidlpHVGZhNldkeloyL0ptaHVQMWFXa1NwMU5OMzNQTWVFQkhMODE2emdjOWowbnRTejdQamNDdVVNSHUvMWpTNklpM1M1QnZQbmtWOFF6V0FDYnc3S2R3SDRXTXRSZlEvcGE4a2hoMUJ3QWR0MGhETitleEJwRmZMVFhTQ0NTK0VlSitvYzYvd2xQZHE4ckRpWFZ1M3c1SExoWGJsQjZLRmsrZEhFcnd6VWl6WDVGeHpEWHd5VXVXQmcrT2NiaDRudUlncitHTzZRUk1BOElaTkhCMmJHNVplV0lmNC9OcVlhNjhQNThtLzVWZTVoUW9FbHhXazY1N2V5RlhHbVM5cUZoV2lNcGZpemwzeTYrWHVqZ1pUaVN2dlMySVF4aXFUaFNmTlM="

func TestAuthMethodCertResourceCreateNew(t *testing.T) {
	name := "test_auth_method_cert"
	path := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_auth_method_cert" "%v" {
			name 				= "%v"
			certificate_data 	= "%v"
			unique_identifier 	= "email"
		}
	`, name, path, CERT_ENCODED)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_cert" "%v" {
			name 				= "%v"
			certificate_data 	= "%v"
			unique_identifier 	= "email"
			bound_ips 			= ["1.1.1.0/32"]
		}
	`, name, path, CERT_ENCODED)

	testAuthMethodResource(t, config, configUpdate, path)
}

func TestAuthMethodApiKeyResourceCreateNew(t *testing.T) {
	name := "test_auth_method"
	path := testPath("path_auth_method")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "%v" {
			name = "%v"
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "%v" {
			name = "%v"
			bound_ips = ["1.1.1.0/32"]
		}
	`, name, path)

	testAuthMethodResource(t, config, configUpdate, path)
}

func TestAuthMethodAWSResourceCreateNew(t *testing.T) {
	name := "test_auth_method_aws_iam"
	path := testPath("path_auth_method_aws_iam")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method_aws_iam" "%v" {
			name = "%v"
			bound_aws_account_id = ["516111111111"]
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_aws_iam" "%v" {
			name = "%v"
			bound_aws_account_id = ["516111111111"]
			bound_ips = ["1.1.1.0/32"]
		}
	`, name, path)

	testAuthMethodResource(t, config, configUpdate, path)
}

func TestAuthMethodSAMLResourceCreateNew(t *testing.T) {
	name := "test_auth_method_saml2"
	path := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_auth_method_saml" "%v" {
			name = "%v"
			idp_metadata_url = "https://dev-1111.okta.com/app/abc12345/sso/saml/metadata"
			unique_identifier = "email"
		}
	`, name, path)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_saml" "%v" {
			name = "%v"
			idp_metadata_url = "https://dev-1111.okta.com/app/abc12345/sso/saml/metadata"
			unique_identifier = "email"
			bound_ips = ["1.1.1.0/32"]
		}
	`, name, path)

	testAuthMethodResource(t, config, configUpdate, path)
}

func TestAuthMethodAzureResourceCreateNew(t *testing.T) {
	name := "test_auth_method_azure_ad"
	path := testPath("path_auth_method_azure_ad")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method_azure_ad" "%v" {
			name = "%v"
			bound_tenant_id = "my-tenant-id"
		}
	`, name, path)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_azure_ad" "%v" {
			name = "%v"
			bound_tenant_id = "my-tenant-id"
			bound_ips = ["1.1.1.0/32"]
			issuer = "https://sts.windows.net/sdfjskfjsdkcsjnc"
		}
	`, name, path)

	testAuthMethodResource(t, config, configUpdate, path)
}

func TestAuthMethodGCPResourceCreateNew(t *testing.T) {
	if os.Getenv("TF_ACC_GCP_SERVICE_ACCOUNT") == "" || os.Getenv("TF_ACC_GCP_BOUND_SERVICE_ACC") == "" {
		return
	}

	name := "test_auth_method_gcp"
	path := testPath("path_auth_method_gcp")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method_gcp" "%v" {
			name = "%v"
			service_account_creds_data = "%v"
			bound_service_accounts = ["%v"]
			type = "gce"
		}
	`, name, path, os.Getenv("TF_ACC_GCP_SERVICE_ACCOUNT"), os.Getenv("TF_ACC_GCP_BOUND_SERVICE_ACC"))

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_gcp" "%v" {
			name = "%v"
			service_account_creds_data = "%v"
			bound_service_accounts = ["%v"]
			type = "gce"
			bound_ips = ["1.1.1.0/32"]
		}
	`, name, path, os.Getenv("TF_ACC_GCP_SERVICE_ACCOUNT"), os.Getenv("TF_ACC_GCP_BOUND_SERVICE_ACC"))

	testAuthMethodResource(t, config, configUpdate, path)
}

func TestAuthMethodUIDResourceCreateNew(t *testing.T) {
	name := "test_auth_method_universal_identity"
	path := testPath("auth_method_universal_identity")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method_universal_identity" "%v" {
			name = "%v"
			deny_inheritance = true
			ttl = 120
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_universal_identity" "%v" {
			name = "%v"
			deny_inheritance = false
			bound_ips = ["1.1.1.0/32"]
		}
	`, name, path)

	testAuthMethodResource(t, config, configUpdate, path)
}

func TestAuthMethodOicdResourceCreateNew(t *testing.T) {
	name := "test_auth_method_oidc"
	path := testPath("auth_method_oidc")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method_oidc" "%v" {
			name = "%v"
			unique_identifier = "email"
			client_secret = "test-client-secret"
			issuer = "https://dev-9yl2unqy.us.auth0.com/"
			client_id = "trst-ci"
			access_expires = 1638741817
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_oidc" "%v" {
			name = "%v"
			unique_identifier = "email2"
			client_secret = "test-client-secret2"
			issuer = "https://dev-9yl2unqy.us.auth0.com/"
			client_id = "trst-ci2"
			bound_ips = ["1.1.1.0/32"]
		}
	`, name, path)

	testAuthMethodResource(t, config, configUpdate, path)
}

func TestAuthMethodOauth2ResourceCreateNew(t *testing.T) {
	name := "tes_akeyless_auth_method_oauth2"
	path := testPath("auth_method_oauth2")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method_oauth2" "%v" {
			name = "%v"
			unique_identifier = "email"
			jwks_uri = "https://test.wixpress.com"
			access_expires = 1638741817
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_oauth2" "%v" {
			name = "%v"
			unique_identifier = "babab"
			jwks_uri = "https://test.wixpress.com"
			bound_ips = ["1.1.1.0/32"]
			access_expires = 1638741817
		}
	`, name, path)

	testAuthMethodResource(t, config, configUpdate, path)
}

func TestAuthMethodK8sResourceCreateNew(t *testing.T) {
	name := "test_auth_method_K8s_3"
	path := testPath("auth_method_K8s_test")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method_k8s" "%v" {
			name = "%v"
			access_expires = 1638741817
			bound_ips = ["1.1.4.0/32"]
			bound_pod_names = ["mypod1", "mypod2"]
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_k8s" "%v" {
			name = "%v"
			access_expires = 1638741817
			bound_ips = ["1.1.4.0/32"]
			bound_pod_names = ["mypod1", "mypod3"]
		}
	`, name, path)

	testAuthMethodResource(t, config, configUpdate, path)
}

func testAuthMethodResource(t *testing.T, config, configUpdate, path string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				//PreConfig: deleteFunc,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
				),
			},
		},
	})
}

func checkMethodExistsRemotelyNew(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GetAuthMethod{
			Name:  path,
			Token: &token,
		}

		_, _, err := client.GetAuthMethod(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}

		return nil
	}
}
