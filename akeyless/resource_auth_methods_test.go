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
	"strings"
	"testing"
	"time"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"
)

var checkAuthMethodDestroyed = func(s *terraform.State) error {
	client := *testAccProvider.Meta().(*providerMeta).client
	token := *testAccProvider.Meta().(*providerMeta).token

	for _, rs := range s.RootModule().Resources {
		if strings.HasPrefix(rs.Type, "akeyless_auth_method") {
			body := akeyless_api.AuthMethodGet{
				Name:  rs.Primary.ID,
				Token: &token,
			}
			_, res, err := client.AuthMethodGet(context.Background()).Body(body).Execute()
			if err == nil {
				return fmt.Errorf("auth method %s still exists", rs.Primary.ID)
			}
			if res != nil && res.StatusCode != 404 {
				return fmt.Errorf("auth method %s: unexpected status %d", rs.Primary.ID, res.StatusCode)
			}
		}
	}
	return nil
}

func TestAuthMethodApiKeyResourceCreateNew(t *testing.T) {
	name := "test_auth_method_api_key"
	path := testPath(name)
	deleteAuthMethod(path, "api_key")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "%v" {
			name 				= "%v"
			access_expires 		= 10000
			bound_ips 			= ["1.1.1.0/32"]
			force_sub_claims 	= true
			jwt_ttl 			= 42
			description 		= "test api key auth method"
			expiration_event_in = ["2","6"]
            audit_logs_claims 	= ["eee","kk"]
			delete_protection 	= "true"
			gw_bound_ips 		= ["2.2.2.0/32"]
			product_type 		= ["sm","sra"]
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "%v" {
			name 				= "/%v"
			access_expires 		= 10001
			bound_ips 			= ["1.1.4.0/32"]
			description 		= "updated api key auth method"
            audit_logs_claims 	= ["eee","kk"]
			delete_protection 	= "false"
			gw_bound_ips 		= ["3.3.3.0/32"]
			product_type 		= ["sm"]
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_api_key."+name, "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_api_key."+name, "description", "test api key auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_api_key."+name, "gw_bound_ips.0", "2.2.2.0/32"),
					resource.TestCheckResourceAttr("akeyless_auth_method_api_key."+name, "product_type.#", "2"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_api_key."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_api_key."+name, "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_api_key."+name, "description", "updated api key auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_api_key."+name, "gw_bound_ips.0", "3.3.3.0/32"),
					resource.TestCheckResourceAttr("akeyless_auth_method_api_key."+name, "product_type.#", "1"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_api_key."+name, "access_id"),
				),
			},
			{
				ResourceName:            "akeyless_auth_method_api_key.test_auth_method_api_key",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"access_key", "jwt_ttl"},
			},
		},
	})
}

func TestAuthMethodAWSResourceCreateNew(t *testing.T) {
	name := "test_auth_method_aws_iam"
	path := testPath("path_auth_method_aws_iam")
	deleteAuthMethod(path, "aws_iam")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_aws_iam" "%v" {
			name 					= "%v"
			description 			= "test aws auth method"
			jwt_ttl 				= 42
			bound_aws_account_id 	= ["516111111111"]
            audit_logs_claims 		= ["eee","kk"]
			delete_protection 		= "true"
			access_expires 			= 1638741817
			force_sub_claims 		= true
			sts_url 				= "https://sts.amazonaws.com"
			bound_arn 				= ["arn:aws:iam::111111111111:role/test"]
			bound_role_name 		= ["testrole"]
			bound_role_id 			= ["AROATEST"]
			bound_resource_id 		= ["i-test123"]
			bound_user_name 		= ["testuser"]
			bound_user_id 			= ["AIDATEST"]
			unique_identifier 		= "test-uid"
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_aws_iam" "%v" {
			name 					= "%v"
			description 			= "updated aws auth method"
			bound_aws_account_id 	= ["516111111111"]
			bound_ips 				= ["1.1.1.0/32"]
            audit_logs_claims 		= ["eee","kk"]
			delete_protection 		= "false"
			access_expires 			= 1638741817
			force_sub_claims 		= false
			sts_url 				= "https://sts.us-east-1.amazonaws.com"
			bound_arn 				= ["arn:aws:iam::222222222222:role/test2"]
			bound_role_name 		= ["testrole2"]
			bound_role_id 			= ["AROATEST2"]
			bound_resource_id 		= ["i-test456"]
			bound_user_name 		= ["testuser2"]
			bound_user_id 			= ["AIDATEST2"]
			unique_identifier 		= "test-uid-updated"
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "description", "test aws auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "access_expires", "1638741817"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "force_sub_claims", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "sts_url", "https://sts.amazonaws.com"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "bound_arn.0", "arn:aws:iam::111111111111:role/test"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "bound_role_name.0", "testrole"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "bound_role_id.0", "AROATEST"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "bound_resource_id.0", "i-test123"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "bound_user_name.0", "testuser"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "bound_user_id.0", "AIDATEST"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "unique_identifier", "test-uid"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_aws_iam."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "description", "updated aws auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "force_sub_claims", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "sts_url", "https://sts.us-east-1.amazonaws.com"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "bound_arn.0", "arn:aws:iam::222222222222:role/test2"),
					resource.TestCheckResourceAttr("akeyless_auth_method_aws_iam."+name, "unique_identifier", "test-uid-updated"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_aws_iam."+name, "access_id"),
				),
			},
			{
				ResourceName:            "akeyless_auth_method_aws_iam.test_auth_method_aws_iam",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"jwt_ttl"},
			},
		},
	})
}

func TestAuthMethodAzureResourceCreateNew(t *testing.T) {
	name := "test_auth_method_azure_ad"
	path := testPath("path_auth_method_azure_ad")
	deleteAuthMethod(path, "azure_ad")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_azure_ad" "%v" {
			name 					= "%v"
			description 			= "test azure auth method"
			jwt_ttl 				= 42
			bound_tenant_id 		= "my-tenant-id"
            audit_logs_claims 		= ["eee","kk"]
			delete_protection 		= "true"
			access_expires 			= 1638741817
			force_sub_claims 		= true
			audience 				= "https://management.azure.com/"
			bound_spid 				= ["sp-test"]
			bound_group_id 			= ["group-test"]
			bound_sub_id 			= ["sub-test"]
			bound_rg_id 			= ["rg-test"]
			bound_providers 		= ["Microsoft.Compute"]
			bound_resource_types 	= ["virtualMachines"]
			bound_resource_names 	= ["test-vm"]
			bound_resource_id 		= ["test-res-id"]
			unique_identifier 		= "test-uid"
		}
	`, name, path)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_azure_ad" "%v" {
			name 					= "%v"
			description 			= "updated azure auth method"
			bound_tenant_id 		= "my-tenant-id"
			bound_ips 				= ["1.1.1.0/32"]
			issuer 					= "https://sts.windows.net/sdfjskfjsdkcsjnc"
            audit_logs_claims 		= ["eee","kk"]
			delete_protection 		= "false"
			access_expires 			= 1638741817
			force_sub_claims 		= false
			audience 				= "https://management.azure.com/updated"
			bound_spid 				= ["sp-test2"]
			bound_group_id 			= ["group-test2"]
			bound_sub_id 			= ["sub-test2"]
			bound_rg_id 			= ["rg-test2"]
			bound_providers 		= ["Microsoft.Network"]
			bound_resource_types 	= ["loadBalancers"]
			bound_resource_names 	= ["test-lb"]
			bound_resource_id 		= ["test-res-id2"]
			unique_identifier 		= "test-uid-updated"
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "description", "test azure auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "access_expires", "1638741817"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "force_sub_claims", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "audience", "https://management.azure.com/"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "bound_spid.0", "sp-test"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "bound_group_id.0", "group-test"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "bound_sub_id.0", "sub-test"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "bound_rg_id.0", "rg-test"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "bound_providers.0", "Microsoft.Compute"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "bound_resource_types.0", "virtualMachines"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "bound_resource_names.0", "test-vm"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "bound_resource_id.0", "test-res-id"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "unique_identifier", "test-uid"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_azure_ad."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "description", "updated azure auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "force_sub_claims", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "audience", "https://management.azure.com/updated"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "bound_spid.0", "sp-test2"),
					resource.TestCheckResourceAttr("akeyless_auth_method_azure_ad."+name, "unique_identifier", "test-uid-updated"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_azure_ad."+name, "access_id"),
				),
			},
		},
	})
}

func TestAuthMethodCertResource(t *testing.T) {
	t.Parallel()
	name := "test_auth_method_cert"
	path := testPath(name)
	deleteAuthMethod(path, "cert")

	cert := generateCert(t)

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_cert" "%v" {
			name 				= "%v"
			jwt_ttl 			= 42
			certificate_data 	= "%v"
			unique_identifier 	= "email"
            audit_logs_claims 	= ["eee","kk"]
			delete_protection 	= "true"
		}
	`, name, path, cert)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_cert" "%v" {
			name 				= "%v"
			certificate_data 	= "%v"
			unique_identifier 	= "uid"
			bound_ips 			= ["1.1.1.0/32"]
            audit_logs_claims 	= ["eee","kk"]
			delete_protection 	= "false"
		}
	`, name, path, cert)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_cert."+name, "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_cert."+name, "unique_identifier", "email"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_cert."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_cert."+name, "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_cert."+name, "unique_identifier", "uid"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_cert."+name, "access_id"),
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
	deleteAuthMethod(path, "gcp")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_gcp" "%v" {
			name 						= "%v"
			jwt_ttl 					= 42
			service_account_creds_data 	= "%v"
			bound_service_accounts 		= ["%v"]
			type 						= "gce"
            audit_logs_claims 			= ["eee","kk"]
			delete_protection 			= "true"
		}
	`, name, path, os.Getenv("TF_ACC_GCP_SERVICE_ACCOUNT"), os.Getenv("TF_ACC_GCP_BOUND_SERVICE_ACC"))

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_gcp" "%v" {
			name 						= "%v"
			service_account_creds_data 	= "%v"
			bound_service_accounts 		= ["%v"]
			type 						= "gce"
			bound_ips 					= ["1.1.1.0/32"]
			delete_protection 			= "false"
		}
	`, name, path, os.Getenv("TF_ACC_GCP_SERVICE_ACCOUNT"), os.Getenv("TF_ACC_GCP_BOUND_SERVICE_ACC"))

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_gcp."+name, "delete_protection", "true"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_gcp."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_gcp."+name, "delete_protection", "false"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_gcp."+name, "access_id"),
				),
			},
		},
	})
}

func TestAuthMethodK8sResourceCreateNew(t *testing.T) {
	name := "test_auth_method_K8s_3"
	path := testPath("auth_method_K8s_test")
	deleteAuthMethod(path, "k8s")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_k8s" "%v" {
			name 				= "%v"
			description 		= "test k8s auth method"
			access_expires 		= 1638741817
			jwt_ttl 			= 42
			bound_ips 			= ["1.1.4.0/32"]
			bound_pod_names 	= ["mypod1", "mypod2"]
            audit_logs_claims 	= ["eee","kk"]
			delete_protection 	= "true"
			force_sub_claims 	= true
			bound_sa_names 		= ["default"]
			bound_namespaces 	= ["kube-system"]
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_k8s" "%v" {
			name 				= "%v"
			description 		= "updated k8s auth method"
			access_expires 		= 1638741817
			bound_ips 			= ["1.1.4.0/32"]
			bound_pod_names 	= ["mypod1", "mypod3"]
            audit_logs_claims 	= ["eee","kk"]
			delete_protection 	= "false"
			force_sub_claims 	= false
			bound_sa_names 		= ["default", "admin"]
			bound_namespaces 	= ["kube-system", "default"]
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_k8s."+name, "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_k8s."+name, "description", "test k8s auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_k8s."+name, "access_expires", "1638741817"),
					resource.TestCheckResourceAttr("akeyless_auth_method_k8s."+name, "force_sub_claims", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_k8s."+name, "bound_sa_names.0", "default"),
					resource.TestCheckResourceAttr("akeyless_auth_method_k8s."+name, "bound_namespaces.0", "kube-system"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_k8s."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_k8s."+name, "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_k8s."+name, "description", "updated k8s auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_k8s."+name, "access_expires", "1638741817"),
					resource.TestCheckResourceAttr("akeyless_auth_method_k8s."+name, "force_sub_claims", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_k8s."+name, "bound_sa_names.#", "2"),
					resource.TestCheckResourceAttr("akeyless_auth_method_k8s."+name, "bound_namespaces.#", "2"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_k8s."+name, "access_id"),
				),
			},
		},
	})
}

func TestAuthMethodLDAPResourceCreateNew(t *testing.T) {
	name := "test_auth_method_ldap"
	path := testPath("auth_method_ldap")
	deleteAuthMethod(path, "ldap")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_ldap" "%v" {
			name 				= "%v"
			description 		= "test ldap auth method"
			access_expires 		= 1638741817
			jwt_ttl 			= 42
			product_type 		= ["sm","sra"]
			audit_logs_claims 	= ["eee","kk"]
			expiration_event_in = ["2","6"]
			delete_protection 	= "true"
			unique_identifier 	= "email"
			gen_key 			= "true"
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_ldap" "%v" {
			name 				= "%v"
			description 		= "test ldap auth method"
			access_expires 		= 1638741817
			jwt_ttl 			= 42
			product_type 		= ["sm"]
			audit_logs_claims 	= ["eee","kk"]
			expiration_event_in = ["2","6"]
			delete_protection 	= "false"
			unique_identifier 	= "username"
			gen_key 			= "true"
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_ldap."+name, "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_ldap."+name, "unique_identifier", "email"),
					resource.TestCheckResourceAttr("akeyless_auth_method_ldap."+name, "description", "test ldap auth method"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_ldap."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_ldap."+name, "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_ldap."+name, "unique_identifier", "username"),
					resource.TestCheckResourceAttr("akeyless_auth_method_ldap."+name, "description", "test ldap auth method"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_ldap."+name, "access_id"),
				),
			},
		},
	})
}

func TestAuthMethodOauth2ResourceCreateNew(t *testing.T) {
	name := "test_akeyless_auth_method_oauth"
	path := testPath("auth_method_oauth")
	deleteAuthMethod(path, "oauth2")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_oauth2" "%v" {
			name 					= "%v"
			description 			= "test oauth2 auth method"
			jwt_ttl 				= 42
			unique_identifier 		= "email"
			jwks_uri 				= "https://test.wixpress.com"
			access_expires 			= 1638741817
            audit_logs_claims 		= ["eee","kk"]
			delete_protection 		= "true"
			force_sub_claims 		= true
			bound_client_ids 		= ["client-1"]
			issuer 					= "https://issuer.example.com"
			audience 				= "test-audience"
			subclaims_delimiters 	= [","]
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_oauth2" "%v" {
			name 					= "%v"
			description 			= "updated oauth2 auth method"
			unique_identifier 		= "babab"
			jwks_uri 				= "https://test.wixpress.com"
			bound_ips 				= ["1.1.1.0/32"]
			access_expires 			= 1638741817
            audit_logs_claims 		= ["eee","kk"]
			delete_protection 		= "false"
			force_sub_claims 		= false
			bound_client_ids 		= ["client-1", "client-2"]
			issuer 					= "https://issuer2.example.com"
			audience 				= "test-audience-updated"
			subclaims_delimiters 	= [",", ";"]
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "description", "test oauth2 auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "unique_identifier", "email"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "force_sub_claims", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "bound_client_ids.0", "client-1"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "issuer", "https://issuer.example.com"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "audience", "test-audience"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "subclaims_delimiters.0", ","),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_oauth2."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "description", "updated oauth2 auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "unique_identifier", "babab"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "force_sub_claims", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "bound_client_ids.#", "2"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "issuer", "https://issuer2.example.com"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "audience", "test-audience-updated"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oauth2."+name, "subclaims_delimiters.#", "2"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_oauth2."+name, "access_id"),
				),
			},
		},
	})
}

func TestAuthMethodOidcResourceCreateNew(t *testing.T) {
	name := "test_auth_method_oidc"
	path := testPath("auth_method_oidc")
	deleteAuthMethod(path, "oidc")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_oidc" "%v" {
			name 					= "%v"
			description 			= "test oidc auth method"
			jwt_ttl 				= 42
			unique_identifier 		= "email"
			client_secret 			= "test-client-secret"
			issuer 					= "https://dev-9yl2unqy.us.auth0.com/"
			client_id 				= "trst-ci"
			access_expires 			= 1638741817
			required_scopes 		= ["email", "profile"]
			required_scopes_prefix 	= "devops"
			delete_protection 		= "true"
			force_sub_claims 		= true
			allowed_redirect_uri 	= ["https://localhost/callback"]
			audience 				= "test-audience"
			subclaims_delimiters 	= [","]
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_oidc" "%v" {
			name 					= "%v"
			description 			= "updated oidc auth method"
			unique_identifier 		= "email2"
			client_secret 			= "test-client-secret2"
			issuer 					= "https://dev-9yl2unqy.us.auth0.com/"
			client_id 				= "trst-ci2"
			bound_ips 				= ["1.1.1.0/32"]
			required_scopes 		= ["id"]
			required_scopes_prefix 	= "rnd"
            audit_logs_claims 		= ["eee","kk"]
			delete_protection 		= "false"
			force_sub_claims 		= false
			allowed_redirect_uri 	= ["https://localhost/callback", "https://localhost/callback2"]
			audience 				= "test-audience-updated"
			subclaims_delimiters 	= [",", ";"]
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "description", "test oidc auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "unique_identifier", "email"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "force_sub_claims", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "allowed_redirect_uri.0", "https://localhost/callback"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "audience", "test-audience"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "subclaims_delimiters.0", ","),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_oidc."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "description", "updated oidc auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "unique_identifier", "email2"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "force_sub_claims", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "allowed_redirect_uri.#", "2"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "audience", "test-audience-updated"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oidc."+name, "subclaims_delimiters.#", "2"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_oidc."+name, "access_id"),
				),
			},
			{
				ResourceName:            "akeyless_auth_method_oidc.test_auth_method_oidc",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"client_secret", "jwt_ttl"},
			},
		},
	})
}

func TestAuthMethodSAMLResourceCreateNew(t *testing.T) {
	name := "test_auth_method_saml"
	path := testPath(name)
	deleteAuthMethod(path, "saml")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_saml" "%v" {
			name 					= "%v"
			description 			= "test saml auth method"
			jwt_ttl 				= 42
			idp_metadata_url 		= "https://dev-1111.okta.com/app/abc12345/sso/saml/metadata"
			unique_identifier 		= "email"
            audit_logs_claims 		= ["eee","kk"]
			delete_protection 		= "true"
			access_expires 			= 1638741817
			force_sub_claims 		= true
			allowed_redirect_uri 	= ["https://localhost/callback"]
			subclaims_delimiters 	= [","]
		}
	`, name, path)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_saml" "%v" {
			name 					= "%v"
			description 			= "updated saml auth method"
			idp_metadata_url 		= "https://dev-1111.okta.com/app/abc12345/sso/saml/metadata"
			unique_identifier 		= "email"
			bound_ips 				= ["1.1.1.0/32"]
            audit_logs_claims 		= ["eee","kk"]
			delete_protection 		= "false"
			access_expires 			= 1638741817
			force_sub_claims 		= false
			allowed_redirect_uri 	= ["https://localhost/callback", "https://localhost/callback2"]
			subclaims_delimiters 	= [",", ";"]
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "description", "test saml auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "unique_identifier", "email"),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "access_expires", "1638741817"),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "force_sub_claims", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "allowed_redirect_uri.0", "https://localhost/callback"),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "subclaims_delimiters.0", ","),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_saml."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "description", "updated saml auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "unique_identifier", "email"),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "force_sub_claims", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "allowed_redirect_uri.#", "2"),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "subclaims_delimiters.#", "2"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_saml."+name, "access_id"),
				),
			},
		},
	})
}

func TestAuthMethodSAMLWithXmlResourceCreateNew(t *testing.T) {
	name := "test_auth_method_saml_xml"
	path := testPath(name)
	deleteAuthMethod(path, "saml")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_saml" "%v" {
			name 					= "%v"
			idp_metadata_xml_data 	= "<ss>cccc<ss>"
			unique_identifier 		= "email"
            audit_logs_claims 		= ["eee","kk"]
		}
	`, name, path)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_saml" "%v" {
			name 					= "%v"
			idp_metadata_xml_data 	= "<ss>ddddd<ss>"
			unique_identifier 		= "email"
			bound_ips 				= ["1.1.1.0/32"]
            audit_logs_claims 		= ["eee","kk"]
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "unique_identifier", "email"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_saml."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_saml."+name, "unique_identifier", "email"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_saml."+name, "access_id"),
				),
			},
		},
	})
}

func TestAuthMethodUIDResourceCreateNew(t *testing.T) {
	name := "test_auth_method_universal_identity"
	path := testPath("auth_method_universal_identity")
	deleteAuthMethod(path, "universal_identity")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_universal_identity" "%v" {
			name 				= "%v"
			description 		= "test uid auth method"
			jwt_ttl 			= 42
			deny_inheritance 	= true
			ttl 				= 120
            audit_logs_claims 	= ["eee","kk"]
			delete_protection 	= "true"
			access_expires 		= 1638741817
			force_sub_claims 	= true
			deny_rotate 		= true
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_universal_identity" "%v" {
			name 				= "%v"
			description 		= "updated uid auth method"
			deny_inheritance 	= false
			bound_ips 			= ["1.1.1.0/32"]
            audit_logs_claims 	= ["eee","kk"]
			delete_protection 	= "false"
			access_expires 		= 1638741817
			force_sub_claims 	= false
			deny_rotate 		= false
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_universal_identity."+name, "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_universal_identity."+name, "description", "test uid auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_universal_identity."+name, "access_expires", "1638741817"),
					resource.TestCheckResourceAttr("akeyless_auth_method_universal_identity."+name, "force_sub_claims", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_universal_identity."+name, "deny_rotate", "true"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_universal_identity."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_universal_identity."+name, "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_universal_identity."+name, "description", "updated uid auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_universal_identity."+name, "force_sub_claims", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_universal_identity."+name, "deny_rotate", "false"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_universal_identity."+name, "access_id"),
				),
			},
		},
	})
}

func TestAuthMethodKerberosResourceCreateNew(t *testing.T) {
	skipIfNoGateway(t)
	t.Parallel()
	name := "test_auth_method_kerberos"
	path := testPath("auth_method_kerberos")
	deleteAuthMethod(path, "kerberos")

	// Base64 encoded test data
	krb5ConfData := "dGVzdC1rcmI1LWNvbmY=" // base64 of "test-krb5-conf"
	keytabData := "dGVzdC1rZXl0YWI="       // base64 of "test-keytab"

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_kerberos" "%v" {
			name 				= "%v"
			jwt_ttl 			= 42
			bind_dn 			= "cn=admin,dc=example,dc=com"
			bind_dn_password 	= "testpassword"
			krb5_conf_data 		= "%v"
			keytab_file_data 	= "%v"
			ldap_url 			= "ldap://ldap.example.com"
            audit_logs_claims 	= ["eee","kk"]
			delete_protection 	= "true"
		}
	`, name, path, krb5ConfData, keytabData)

	krb5ConfDataUpdated := "dGVzdC1rcmI1LWNvbmYtdXBkYXRlZA==" // base64 of "test-krb5-conf-updated"
	keytabDataUpdated := "dGVzdC1rZXl0YWItdXBkYXRlZA=="       // base64 of "test-keytab-updated"

	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_kerberos" "%v" {
			name 				= "%v"
			bind_dn 			= "cn=admin2,dc=example,dc=com"
			bind_dn_password 	= "testpassword2"
			krb5_conf_data 		= "%v"
			keytab_file_data 	= "%v"
			ldap_url 			= "ldap://ldap2.example.com"
			bound_ips 			= ["1.1.1.0/32"]
            audit_logs_claims 	= ["eee","kk"]
			delete_protection 	= "false"
		}
	`, name, path, krb5ConfDataUpdated, keytabDataUpdated)

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

func TestAuthMethodOCIResourceCreateNew(t *testing.T) {
	name := "test_auth_method_oci"
	path := testPath("auth_method_oci")
	deleteAuthMethod(path, "oci")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_oci" "%v" {
			name 				= "%v"
			description 		= "test oci auth method"
			jwt_ttl 			= 42
			tenant_ocid 		= "ocid1.tenancy.oc1..test"
			group_ocid 			= ["ocid1.group.oc1..test"]
            audit_logs_claims 	= ["eee","kk"]
			delete_protection 	= "true"
			access_expires 		= 1638741817
			force_sub_claims 	= true
		}
	`, name, path)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_auth_method_oci" "%v" {
			name 				= "%v"
			description 		= "updated oci auth method"
			tenant_ocid 		= "ocid1.tenancy.oc1..test2"
			group_ocid 			= ["ocid1.group.oc1..test2"]
			bound_ips 			= ["1.1.1.0/32"]
            audit_logs_claims 	= ["eee","kk"]
			delete_protection 	= "false"
			access_expires 		= 1638741817
			force_sub_claims 	= false
		}
	`, name, path)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_oci."+name, "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oci."+name, "description", "test oci auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oci."+name, "access_expires", "1638741817"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oci."+name, "force_sub_claims", "true"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_oci."+name, "access_id"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkMethodExistsRemotelyNew(path),
					resource.TestCheckResourceAttr("akeyless_auth_method_oci."+name, "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oci."+name, "description", "updated oci auth method"),
					resource.TestCheckResourceAttr("akeyless_auth_method_oci."+name, "force_sub_claims", "false"),
					resource.TestCheckResourceAttrSet("akeyless_auth_method_oci."+name, "access_id"),
				),
			},
		},
	})
}

func checkMethodExistsRemotelyNew(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		gsvBody := akeyless_api.AuthMethodGet{
			Name:  path,
			Token: &token,
		}

		_, _, err := client.AuthMethodGet(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}

		return nil
	}
}

func testAuthMethodResource(t *testing.T, config, configUpdate, path string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkAuthMethodDestroyed,
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
