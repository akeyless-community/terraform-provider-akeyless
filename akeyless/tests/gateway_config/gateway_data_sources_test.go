package gateway_config

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestK8sAuthConfigDataSource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "test_k8s_auth_ds"
	rsaKeyB64 := testutils.GenerateKey(2048)
	dummyJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCJ9.dGVzdHNpZ25hdHVyZQ"

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "k8s_auth_am_ds" {
			name = "%v"
		}
		resource "akeyless_k8s_auth_config" "%v" {
			name                      = "%v"
			access_id                 = akeyless_auth_method_api_key.k8s_auth_am_ds.access_id
			signing_key               = "%v"
			k8s_host                  = "https://k8s-api.example.com:6443"
			k8s_ca_cert               = "dGVzdA=="
			token_reviewer_jwt        = "%v"
			disable_issuer_validation = "true"
			depends_on                = [akeyless_auth_method_api_key.k8s_auth_am_ds]
		}
		data "akeyless_k8s_auth_config" "read" {
			name       = "%v"
			depends_on = [akeyless_k8s_auth_config.%v]
		}
	`, testPath("k8s_auth_am_ds"), name, testPath(name), rsaKeyB64, dummyJWT, testPath(name), name)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.akeyless_k8s_auth_config.read", "auth_method_access_id"),
					resource.TestCheckResourceAttrSet("data.akeyless_k8s_auth_config.read", "k8s_host"),
				),
			},
		},
	})
}
