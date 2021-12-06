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

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
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

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
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

func TestAuthMethodSAMLResourceCreateNew(t *testing.T) {
	name := "test_auth_method_saml"
	path := testPath("path_auth_method_saml")
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

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
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

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
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
		}
	`, name, path, os.Getenv("TF_ACC_GCP_SERVICE_ACCOUNT"), os.Getenv("TF_ACC_GCP_BOUND_SERVICE_ACC"))

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_gcp" "%v" {
			name = "%v"
			service_account_creds_data = "%v"
			bound_service_accounts = ["%v"]
			bound_ips = ["1.1.1.0/32"]
		}
	`, name, path, os.Getenv("TF_ACC_GCP_SERVICE_ACCOUNT"), os.Getenv("TF_ACC_GCP_BOUND_SERVICE_ACC"))

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
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

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
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

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
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

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
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

func TestAuthMethodK8sResourceCreateNew(t *testing.T) {
	name := "test_auth_method_K8s"
	path := testPath("auth_method_K8s")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method_k8s" "%v" {
			name = "%v"
			access_expires = 1638741817
			bound_ips = ["1.1.4.0/32"]
			public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KmDcjfruwSq6o5M8+Y3uiWpfNIU71KOWp19i/wWvPbmWgH8MzE+OECzI6Kh1Rp+x4ASDDHg3aDyUSUpGJoX9YvldyPISnp76J2HSlgMri+QQnae5JKC4mzTEdsNXbrw3hZceWuge22/yo4YfPbXmRl5S6Xam/etUqmxYCqUVR98gxu8tTPJAON3Ieg10lmw8DqL41V0+rScwAAacHed6RZzCCqegqmuX0Bqtt2zvwxCoQwS9rk62CrsySfsb1U/1CBzjRKULGCxOT1lVHLqX/IjpGPsgQZZAn0BfxNa/snhTgyp7LXFhBY5iVcMD0KwHy6PqVwdRQ1hZGW/xjidXwIDAQAB"
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_k8s" "%v" {
			name = "%v"
			bound_ips = ["1.1.1.0/32"]
			access_expires = 1638941817
			public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0KmDcjfruwSq6o5M8+Y3uiWpfNIU71KOWp19i/wWvPbmWgH8MzE+OECzI6Kh1Rp+x4ASDDHg3aDyUSUpGJoX9YvldyPISnp76J2HSlgMri+QQnae5JKC4mzTEdsNXbrw3hZceWuge22/yo4YfPbXmRl5S6Xam/etUqmxYCqUVR98gxu8tTPJAON3Ieg10lmw8DqL41V0+rScwAAacHed6RZzCCqegqmuX0Bqtt2zvwxCoQwS9rk62CrsySfsb1U/1CBzjRKULGCxOT1lVHLqX/IjpGPsgQZZAn0BfxNa/snhTgyp7LXFhBY5iVcMD0KwHy6PqVwdRQ1hZGW/xjidXwIDAQAB"
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
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
