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
			bound_ips = ["123.3.13.3"]
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
			bound_ips = ["123.3.13.3"]
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
			bound_ips = ["123.3.13.3"]
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
			bound_ips = ["123.3.13.3"]
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
			bound_ips = ["123.3.13.3"]
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
			access_expires = 1638741817
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_universal_identity" "%v" {
			name = "%v"
			deny_inheritance = false
			bound_ips = ["123.3.13.3"]
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
