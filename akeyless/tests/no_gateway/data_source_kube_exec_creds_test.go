package no_gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestKubeExecCredsDataSource(t *testing.T) {
	t.Parallel()

	privateKey, _ := testutils.GenerateKeyAndCsrForTest(1024)
	keyName := "test-dfc-for-kube-exec"
	keyPath := testPath(keyName)
	testutils.CreateDfcKey(t, keyPath)
	t.Cleanup(func() { testutils.DeleteItem(t, keyPath) })

	name := "test-pki-for-kube-exec"
	itemPath := testPath(name)
	destPath := "terraform-tests"
	cn := "cn-kube-exec"
	uriSan := "uri-kube-exec"
	testutils.CreatePkiCertIssuer(t, keyPath, itemPath, destPath, cn, uriSan)
	t.Cleanup(func() { testutils.DeleteItem(t, itemPath) })
	certPath := fmt.Sprintf("/%s/%s", destPath, cn)
	t.Cleanup(func() { testutils.DeleteItem(t, certPath) })

	config := fmt.Sprintf(`
		data "akeyless_kube_exec_creds" "exec" {
			cert_issuer_name  = "%v"
			key_data_base64   = "%v"
			common_name       = "%v"
			alt_names         = "%v"
			uri_sans          = "%v"
			ttl               = "120"
			extended_key_usage = "clientauth"
		}
	`, itemPath, privateKey, cn, cn, uriSan)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.akeyless_kube_exec_creds.exec", "api_version"),
					resource.TestCheckResourceAttrSet("data.akeyless_kube_exec_creds.exec", "kind"),
					resource.TestCheckResourceAttrSet("data.akeyless_kube_exec_creds.exec", "client_certificate_data"),
				),
			},
		},
	})
}
