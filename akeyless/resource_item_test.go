package akeyless

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"
)

const (
	PUBLIC_KEY  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	PRIVATE_KEY = "XXXXXXXX"
)

func TestDfcKeyRsaResource(t *testing.T) {
	t.Parallel()

	name := "test_rsa_key"
	itemPath := testPath(name)
	deleteItem(t, itemPath)

	config := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name = "%v"
			tags     = ["t1", "t2"]
			alg = "RSA1024"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name = "%v"	
			tags     = ["t1", "t3"]
			alg = "RSA1024"
		}
	`, name, itemPath)

	tesItemResource(t, config, configUpdate, itemPath)

}

func TestRsaPublicResource(t *testing.T) {
	t.Parallel()

	name := "test_rsa_pub_key"
	itemPath := testPath(name)
	deleteItem(t, itemPath)

	config := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name = "%v"
			alg = "RSA2048"
		}
		data "akeyless_rsa_pub" "%v_2" {
			name = akeyless_dfc_key.%v.name
		}
	`, name, itemPath, name, name)

	configUpdate := config

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestDfcKeyResource(t *testing.T) {
	t.Parallel()

	name := "test_dfc_key"
	itemPath := testPath("path_dfc_key12")
	config := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name = "%v"
			tags     = ["t1", "t2"]
			alg = "AES128SIV"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name = "%v"	
			tags     = ["t1", "t3"]
			alg = "AES128SIV"
		}
	`, name, itemPath)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestClassicKey(t *testing.T) {

	t.Skip("not authorized to create producer on public gateway")
	t.Parallel()

	name := "test_classic_key"
	itemPath := testPath(name)
	deleteItem(t, itemPath)

	config := fmt.Sprintf(`
		resource "akeyless_classic_key" "%v" {
			name 		= "%v"
			alg 		= "RSA2048"
			tags 		= ["aaaa", "bbbb"]
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_classic_key" "%v" {
			name 		= "%v"	
			alg 		= "RSA2048"
			tags 		= ["cccc", "dddd"]
			metadata 	= "abcd"
		}
	`, name, itemPath)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestPkiResource(t *testing.T) {
	t.Parallel()

	name := "test_pki"
	itemPath := testPath("path_pki")
	deleteItem(t, "terraform-tests/test_pki_key")

	config := fmt.Sprintf(`
		resource "akeyless_dfc_key" "key" {
			name = "terraform-tests/test_pki_key"
			alg = "RSA1024"
		}
		resource "akeyless_pki_cert_issuer" "%v" {
			name = "%v"
			ttl = "390"
			signer_key_name = "/terraform-tests/test_pki_key"
			tags     = ["t1", "t2"]
			allow_subdomains = true
			allowed_domains = "jdjdjd"

			depends_on = [
    			akeyless_dfc_key.key,
  			]
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dfc_key" "key" {
			name = "terraform-tests/test_pki_key"
			alg = "RSA1024"
			tags     = ["t1", "t2"]
		}

		resource "akeyless_pki_cert_issuer" "%v" {
			name = "%v"
			ttl = "390"
			allow_subdomains = false
			tags     = ["t1", "t3"]
			allowed_domains = "ddd,dss"
			signer_key_name = "/terraform-tests/test_pki_key"
			depends_on = [
    			akeyless_dfc_key.key,
  			]
		}
	`, name, itemPath)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestPkiDataSource(t *testing.T) {
	t.Parallel()
	t.Skip("for now the requested values are fictive")

	keyName := "test_pki_key"
	keyPath := testPath(keyName)
	certName := "test_pki_cert"
	certPath := testPath(certName)
	config := fmt.Sprintf(`
		resource "akeyless_dfc_key" "key" {
			name 				= "%v"
			alg 				= "RSA1024"
		}
		resource "akeyless_pki_cert_issuer" "%v" {
			name 				= "%v"
			signer_key_name 	= "/%v"
			ttl 				= "390"
			allowed_domains 	= "aaaa"
			depends_on = [
				akeyless_dfc_key.key,
			]
		}
		data "akeyless_pki_certificate" "pki_cert" {
			cert_issuer_name  	= "%v"
			key_data_base64   	= "%v"
			common_name       	= "aaaa"
			depends_on = [
				akeyless_pki_cert_issuer.%v,
			]
		}
	`, keyPath, certName, certPath, keyPath, certPath, PRIVATE_KEY, certName)

	configUpdate := config

	tesItemResource(t, config, configUpdate, certPath)
}

func TestSshCertResource(t *testing.T) {
	t.Parallel()

	name := "test_ssh"
	itemPath := testPath("path_ssh")
	deleteItem(t, "/terraform-tests/test_ssh_key")

	config := fmt.Sprintf(`
		resource "akeyless_dfc_key" "key_ssh" {
			name = "terraform-tests/test_ssh_key"
			alg = "RSA1024"
		}
		resource "akeyless_ssh_cert_issuer" "%v" {
			name = "%v"
			ttl = "390"
			signer_key_name = "/terraform-tests/test_ssh_key"
			tags     = ["t1", "t2"]
			allowed_users = "aaaa"
			secure_access_enable = "true"
			secure_access_host = ["1.1.1.1", "2.2.2.2"]
			secure_access_bastion_api = "https://my.bastion:9900"
			secure_access_bastion_ssh = "my.bastion:22"
			secure_access_ssh_creds_user = "aaaa"

			depends_on = [
    			akeyless_dfc_key.key_ssh,
  			]
		}
		data "akeyless_ssh_certificate" "ssh_cert" {
			cert_username     = "aaaa"
			cert_issuer_name  = "%v"
			public_key_data   = "%v"
			depends_on = [
				akeyless_ssh_cert_issuer.%v,
			]
		}
	`, name, itemPath, itemPath, PUBLIC_KEY, name)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_dfc_key" "key_ssh" {
			name = "terraform-tests/test_ssh_key"
			alg = "RSA1024"
			tags     = ["t1", "t2"]
		}

		resource "akeyless_ssh_cert_issuer" "%v" {
			name = "%v"
			ttl = "290"
			signer_key_name = "/terraform-tests/test_ssh_key"
			tags     = ["t1", "t3"]
			allowed_users = "aaaa2,fffff"
			secure_access_enable = "true"
			secure_access_host = ["1.1.1.1", "2.2.2.2"]
			secure_access_bastion_api = "https://my.bastion:9901"
			secure_access_bastion_ssh = "my.bastion1:22"
			secure_access_ssh_creds_user = "aaaa2"

			depends_on = [
    			akeyless_dfc_key.key_ssh,
  			]
		}
		data "akeyless_ssh_certificate" "ssh_cert" {
			cert_username     = "aaaa2"
			cert_issuer_name  = "%v"
			public_key_data   = "%v"
			depends_on = [
				akeyless_ssh_cert_issuer.%v,
			]
		}
	`, name, itemPath, itemPath, PUBLIC_KEY, name)

	tesItemResource(t, config, configUpdate, itemPath)
}

func deleteItem(t *testing.T, path string) {

	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	gsvBody := akeyless.DeleteItem{
		Name:              path,
		DeleteImmediately: akeyless.PtrBool(true),
		DeleteInDays:      akeyless.PtrInt64(-1),
		Token:             &token,
	}

	client.DeleteItem(context.Background()).Body(gsvBody).Execute()
}

func tesItemResource(t *testing.T, config, configUpdate, itemPath string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				//PreConfig: deleteFunc,
				Check: resource.ComposeTestCheckFunc(
					checkItemExistsRemotely(itemPath),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkItemExistsRemotely(itemPath),
				),
			},
		},
	})
}

func checkItemExistsRemotely(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.DescribeItem{
			Name:         path,
			ShowVersions: akeyless.PtrBool(false),
			Token:        &token,
		}

		_, _, err := client.DescribeItem(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}
		return nil
	}
}

func getProviderMeta() (*providerMeta, error) {

	apiGwAddress := os.Getenv("AKEYLESS_GATEWAY")
	if apiGwAddress == "" {
		apiGwAddress = publicApi
	}
	client := akeyless.NewAPIClient(&akeyless.Configuration{
		Servers: []akeyless.ServerConfiguration{
			{
				URL: apiGwAddress,
			},
		},
	}).V2Api

	authBody := akeyless.NewAuthWithDefaults()
	authBody.AccessId = akeyless.PtrString(os.Getenv("AKEYLESS_ACCESS_ID"))
	authBody.AccessKey = akeyless.PtrString(os.Getenv("AKEYLESS_ACCESS_KEY"))
	authBody.AccessType = akeyless.PtrString(common.ApiKey)

	ctx := context.Background()

	authOut, _, err := client.Auth(ctx).Body(*authBody).Execute()
	if err != nil {
		return nil, err

	}
	token := authOut.GetToken()

	return &providerMeta{client, &token}, nil
}
