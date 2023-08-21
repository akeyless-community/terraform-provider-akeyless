package akeyless

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"
)

func TestAuthMethodCertResource(t *testing.T) {
	t.Parallel()
	name := "test_auth_method_cert"
	path := testPath(name)

	cert := generateCert(t)

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_cert" "%v" {
			name 				= "%v"
			certificate_data 	= "%v"
			unique_identifier 	= "email"
		}
	`, name, path, cert)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_cert" "%v" {
			name 				= "%v"
			certificate_data 	= "%v"
			unique_identifier 	= "uid"
			bound_ips 			= ["1.1.1.0/32"]
		}
	`, name, path, cert)

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
	name := "test_auth_method_saml2"
	path := testPath(name)
	deleteAuthMethod(path)

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

func TestAuthMethodSAMLWithXmlResourceCreateNew(t *testing.T) {
	name := "test_auth_method_saml_xml"
	path := testPath(name)
	deleteAuthMethod(path)

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_saml" "%v" {
			name = "%v"
			idp_metadata_xml_data = "<ss>cccc<ss>"
			unique_identifier = "email"
		}
	`, name, path)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_saml" "%v" {
			name = "%v"
			idp_metadata_xml_data = "<ss>ddddd<ss>"
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

func TestAuthMethodOidcResourceCreateNew(t *testing.T) {
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
			required_scopes = ["email", "profile"]
			required_scopes_prefix = "devops"
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
			required_scopes = ["id"]
			required_scopes_prefix = "rnd"
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

func generateCert(t *testing.T) string {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(20202),
		Subject: pkix.Name{
			Organization: []string{"akeyless.io"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 3, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	certBytes := caPEM.Bytes()
	cert := base64.StdEncoding.EncodeToString(certBytes)
	return cert
}
