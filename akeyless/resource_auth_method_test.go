package akeyless

import (
	"context"
	"fmt"
	"os"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAuthMethodApiKeyResourceCreate(t *testing.T) {
	name := "test_auth_method"
	path := testPath("path_auth_method")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "%v" {
			path = "%v"
			api_key {
			}
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotely(path),
				),
			},
		},
	})
}

func TestAuthMethodAWSResourceCreate(t *testing.T) {
	name := "test_auth_method_aws_iam"
	path := testPath("path_auth_method_aws_iam")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "%v" {
			path = "%v"
			aws_iam {
				bound_aws_account_id = ["516111111111"]
			}
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotely(path),
				),
			},
		},
	})
}

func TestAuthMethodSAMLResourceCreate(t *testing.T) {
	name := "test_auth_method_saml"
	path := testPath("path_auth_method_saml")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "%v" {
			path = "%v"
			saml {
				idp_metadata_url = "https://dev-1111.okta.com/app/abc12345/sso/saml/metadata"
				unique_identifier = "email"
			}
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotely(path),
				),
			},
		},
	})
}

func TestAuthMethodAzureResourceCreate(t *testing.T) {
	name := "test_auth_method_azure_ad"
	path := testPath("path_auth_method_azure_ad")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "%v" {
			path = "%v"
			azure_ad {
				bound_tenant_id = "my-tenant-id"
			}
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotely(path),
				),
			},
		},
	})
}

func TestAuthMethodGCPResourceCreate(t *testing.T) {
	if os.Getenv("TF_ACC_GCP_SERVICE_ACCOUNT") == "" || os.Getenv("TF_ACC_GCP_BOUND_SERVICE_ACC") == "" {
		return
	}

	name := "test_auth_method_gcp"
	path := testPath("path_auth_method_gcp")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "%v" {
			path = "%v"
			gcp {
				service_account_creds_data = "%v"
				iam {
					bound_service_accounts = ["%v"]
				}
			}
		}
	`, name, path, os.Getenv("TF_ACC_GCP_SERVICE_ACCOUNT"), os.Getenv("TF_ACC_GCP_BOUND_SERVICE_ACC"))

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotely(path),
				),
			},
		},
	})
}

func checkMethodExistsRemotely(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		gsvBody := akeyless_api.GetAuthMethod{
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
