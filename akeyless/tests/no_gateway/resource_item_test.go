package no_gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestDfcKeyRsaResource(t *testing.T) {
	t.Parallel()
	name := "test_rsa_key"
	itemPath := testPath(name)
	certPem, _ := testutils.GenerateCertForTestWithKey(t, 1024, itemPath)
	config := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 								= "%v"
			alg 								= "RSA1024"
			description 						= "aaaa"
			split_level 						= 2
			generate_self_signed_certificate 	= true
			certificate_ttl 					= 60
			certificate_common_name 			= "cn1"
			certificate_organization 			= "org1"
			certificate_country 				= "cntry1"
			certificate_locality 				= "local1"
			certificate_province 				= "prov1"
			tags        						= ["t1","t2"]
			delete_protection 					= true
			certificate_format = "der"
			expiration_event_in = ["20"]
		}
	`, name, itemPath)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 								= "%v"
			alg 								= "RSA1024"
			description 						= "bbbb"
			split_level 						= 2
			generate_self_signed_certificate 	= true
			certificate_ttl 					= 60
			certificate_common_name 			= "cn1"
			certificate_organization 			= "org1"
			certificate_country 				= "cntry1"
			certificate_locality 				= "local1"
			certificate_province 				= "prov1"
			cert_data_base64 					= "%v"
			tags        						= ["t1","t3"]
			certificate_format = "pem"
			expiration_event_in = ["21"]
		}
	`, name, itemPath, certPem)
	configUpdate2 := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name 								= "%v"
			alg 								= "RSA1024"
			description 						= "bbbb"
			split_level 						= 2
			generate_self_signed_certificate 	= true
			certificate_ttl 					= 60
			certificate_common_name 			= "cn1"
			certificate_organization 			= "org1"
			certificate_country 				= "cntry1"
			certificate_locality 				= "local1"
			certificate_province 				= "prov1"
			cert_data_base64 					= "%v"
			tags        						= ["t1","t3"]
			certificate_format = "der"
			expiration_event_in = ["21"]
		}
	`, name, itemPath, certPem)
	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate, configUpdate2)
}

func TestDfcKeyAesResource(t *testing.T) {
	t.Parallel()
	name := "test_dfc_key"
	itemPath := testPath("path_dfc_key")
	config := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name = "%v"
			tags     = ["t1", "t2"]
			alg = "AES128SIV"
			certificate_format = "pem"
			auto_rotate = "true"
            split_level = "2"
			rotation_interval = "7"
			rotation_event_in = ["10"]
			expiration_event_in = ["20"]
		}
	`, name, itemPath)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name = "%v"	
			tags     = ["t1", "t3"]
			alg = "AES128SIV"
			certificate_format = "der"
			auto_rotate = "true"
            split_level = "2"
			rotation_interval = "7"
			rotation_event_in = ["10"]
			expiration_event_in = ["15"]
		}
	`, name, itemPath)
	configUpdate2 := fmt.Sprintf(`
		resource "akeyless_dfc_key" "%v" {
			name = "%v"	
			tags     = ["t1", "t3"]
			alg = "AES128SIV"
			certificate_format = "pem"
			auto_rotate = "true"
            split_level = "2"
			rotation_interval = "7"
			rotation_event_in = ["10"]
			expiration_event_in = ["15"]
		}
	`, name, itemPath)
	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate, configUpdate2)
}

func TestRsaPublicResource(t *testing.T) {
	t.Parallel()
	name := "test_rsa_pub_key"
	itemPath := testPath(name)
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
	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestPkiResource(t *testing.T) {
	t.Parallel()
	keyPath := testPath("test-dfc-for-pki")
	testutils.CreateDfcKey(t, keyPath)
	defer testutils.DeleteItem(t, keyPath)
	name := "test-pki-resource"
	itemPath := testPath(name)
	config := fmt.Sprintf(`
		resource "akeyless_pki_cert_issuer" "%v" {
			name 					= "%v"
			signer_key_name 		= "/%v"
			ttl                   	= "50"
			destination_path      	= "/terraform-tests"
			allowed_domains       	= "domains"
			allowed_uri_sans      	= "uri_sans"
			allow_subdomains      	= true
			not_enforce_hostnames 	= false
			allow_any_name        	= true
			not_require_cn        	= true
			server_flag           	= true
			client_flag           	= true
			code_signing_flag     	= true
			key_usage             	= "KeyAgreement,KeyEncipherment"
			critical_key_usage    	= "false"
			organizational_units  	= "org1"
			country               	= "coun1"
			locality              	= "loca1"
			province              	= "prov1"
			street_address        	= "stre1"
			postal_code           	= "post1"
			protect_certificates  	= true
			is_ca                   = true
			basic_constraints       = "critical,CA:true,pathlen:0"
			enable_acme             = false
			max_path_len          	= 0
			expiration_event_in   	= ["1"]
			allowed_extra_extensions = "{\"1.2.3.4.5\":[\"value1\",\"value2\"],\"1.2.3.4.6\":[\"value3\",\"value4\"]}"
			allow_copy_ext_from_csr = true
			description           	= "desc1"
			tags     			  	= ["t1", "t2"]
			delete_protection     	= "true"
		}
	`, name, itemPath, keyPath)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_pki_cert_issuer" "%v" {
			name 					= "%v"
			signer_key_name 		= "/%v"
			ttl                   	= "51s"
			destination_path      	= "/terraform-tests"
			allowed_domains       	= "domain1,domain2"
			allowed_uri_sans      	= "uri_san1,uri_san2"
			allowed_ip_sans       	= "1.1.1.1/32,2.2.2.2/32"
			allow_subdomains      	= false
			not_enforce_hostnames 	= true
			allow_any_name        	= false
			not_require_cn        	= true
			server_flag           	= false
			client_flag           	= false
			code_signing_flag     	= false
			key_usage             	= "DigitalSignature"
			critical_key_usage    	= "true"
			organizational_units  	= "org1,org2"
			country               	= "coun2"
			locality              	= "loca2"
			province              	= "prov2"
			street_address        	= "stre2"
			postal_code           	= "post2"
			protect_certificates  	= false
			is_ca                   = false
			basic_constraints       = "CA:false"
			enable_acme             = false
			max_path_len          	= 0
			expiration_event_in   	= []
			allowed_extra_extensions = "{\"1.2.3.4.5\":[\"value1\",\"value5\"]}"
			allow_copy_ext_from_csr = false
			description           	= "desc2"
			tags     			  	= ["t1", "t3"]
		}
	`, name, itemPath, keyPath)
	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestPkiDataSource(t *testing.T) {
	t.Parallel()
	privateKey, csr := testutils.GenerateKeyAndCsrForTest(1024)
	keyName := "test-dfc-for-pki-test"
	keyPath := testPath(keyName)
	testutils.CreateDfcKey(t, keyPath)
	defer testutils.DeleteItem(t, keyPath)
	name := "test-pki-data"
	itemPath := testPath(name)
	destPath := "terraform-tests"
	cn := "cn1"
	uriSan := "uri1"
	testutils.CreatePkiCertIssuer(t, keyPath, itemPath, destPath, cn, uriSan)
	defer testutils.DeleteItem(t, itemPath)
	certPath := fmt.Sprintf("/%s/%s", destPath, cn)
	defer testutils.DeleteItem(t, certPath)
	config1 := fmt.Sprintf(`
		data "akeyless_pki_certificate" "pki_cert" {
			cert_issuer_name  	= "%v"
			key_data_base64   	= "%v"
			common_name         = "%v"
			alt_names           = "%v"
			uri_sans            = "%v"
			ttl                 = 120
			extended_key_usage  = "clientauth"
		}
		output "pki" {
			value     = data.akeyless_pki_certificate.pki_cert
			sensitive = true
		}
	`, itemPath, privateKey, cn, cn, uriSan)
	testutils.TesItemDataSource(t, providerFactories, config1, "pki", []string{"data", "parent_cert"})
	config2 := fmt.Sprintf(`
		data "akeyless_pki_certificate" "pki_cert" {
			cert_issuer_name  	= "%v"
			csr_data_base64     = "%v"
			common_name         = "%v"
			ttl                 = 120
			extended_key_usage  = "clientauth"
		}
		output "pki" {
			value     = data.akeyless_pki_certificate.pki_cert
			sensitive = true
		}
	`, itemPath, csr, cn)
	testutils.TesItemDataSource(t, providerFactories, config2, "pki", []string{"data", "parent_cert"})
}

func TestSshCertResource(t *testing.T) {
	t.Parallel()
	name := "test_ssh"
	itemPath := testPath(name)
	defer testutils.DeleteItem(t, itemPath)
	key := "test_ssh_key"
	keyPath := testPath(key)
	defer testutils.DeleteItem(t, keyPath)
	config := fmt.Sprintf(`
		resource "akeyless_dfc_key" "key_ssh" {
			name = "%v"
			alg = "RSA1024"
		}
		resource "akeyless_ssh_cert_issuer" "%v" {
			name 							= "%v"
			ttl 							= "500"
			signer_key_name 				= "/%v"
			tags     						= ["t1", "t2"]
			allowed_users 					= "aaaa"
			secure_access_enable 			= "true"
			secure_access_host 				= ["1.1.1.1", "2.2.2.2"]
			secure_access_bastion_api 		= "https://my.bastion:9900"
			secure_access_bastion_ssh 		= "my.bastion:22"
			secure_access_ssh_creds_user 	= "aaaa"
			delete_protection 				= true

			depends_on = [
    			akeyless_dfc_key.key_ssh,
  			]
		}
	`, keyPath, name, itemPath, keyPath)
	configUpdate := fmt.Sprintf(`
			resource "akeyless_dfc_key" "key_ssh" {
			name = "%v"
			alg = "RSA1024"
			tags     = ["t1", "t2"]
		}

		resource "akeyless_ssh_cert_issuer" "%v" {
			name 							= "%v"
			ttl 							= "290"
			signer_key_name 				= "/%v"
			tags     						= ["t1", "t3"]
			allowed_users 					= "aaaa2,fffff"
			secure_access_enable 			= "true"
			secure_access_host 				= ["1.1.1.1", "2.2.2.2"]
			secure_access_bastion_api 		= "https://my.bastion:9901"
			secure_access_bastion_ssh 		= "my.bastion1:22"
			secure_access_ssh_creds_user 	= "aaaa2"

			depends_on = [
    			akeyless_dfc_key.key_ssh,
  			]
		}
	`, keyPath, name, itemPath, keyPath)
	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestSshDataSource(t *testing.T) {
	t.Parallel()
	keyName := "test-dfc-for-ssh-test"
	keyPath := testPath(keyName)
	testutils.CreateDfcKey(t, keyPath)
	defer testutils.DeleteItem(t, keyPath)
	rsaPublicKey := testutils.GetRsaPublicKey(t, keyPath)
	sshPublicKey := *rsaPublicKey.Ssh
	name := "test-ssh-data"
	itemPath := testPath(name)
	allowedUser := "tf_user"
	testutils.CreateSshCertIssuer(t, keyPath, itemPath, allowedUser)
	defer testutils.DeleteItem(t, itemPath)
	config1 := fmt.Sprintf(`
		data "akeyless_ssh_certificate" "ssh_cert" {
			cert_issuer_name  		= "%v"
			cert_username     		= "%v"
			public_key_data   		= "%v"
			ttl 					= 120
		}
		output "ssh" {
			value     = data.akeyless_ssh_certificate.ssh_cert
			sensitive = true
		}
	`, itemPath, allowedUser, sshPublicKey)
	testutils.TesItemDataSource(t, providerFactories, config1, "ssh", []string{"data"})
	config2 := fmt.Sprintf(`
		data "akeyless_ssh_certificate" "ssh_cert" {
			cert_issuer_name  		= "%v"
			cert_username     		= "%v"
			public_key_data   		= "%v"
			ttl 					= 180
			legacy_signing_alg_name = true
		}
		output "ssh" {
			value     = data.akeyless_ssh_certificate.ssh_cert
			sensitive = true
		}
	`, itemPath, allowedUser, sshPublicKey)
	testutils.TesItemDataSource(t, providerFactories, config2, "ssh", []string{"data"})
}

func TestCsrDataSource(t *testing.T) {
	t.Parallel()
	keyName := "test-classic-key-for-csr"
	keyPath := testPath(keyName)
	defer testutils.DeleteItem(t, keyPath)
	config := fmt.Sprintf(`
		data "akeyless_csr" "test_csr" {
			name              = "%v"
			common_name       = "test"
			generate_key      = true
			key_type          = "dfc"
			alg               = "RSA2048"
			certificate_type  = "ssl-client"
			critical          = true
			org               = "org1"
			dep               = "dep1"
			city              = "city1"
			state             = "state1"
			country           = "country1"
			alt_names         = "test1.com,test2.com"
			email_addresses   = "test1@gmail.com, test2@gmail.com"
			ip_addresses      = "192.168.0.1,192.168.0.2"
			uri_sans          = "uri1.com,uri2.com"
			split_level       = 2
		}

		output "csr" {
			value     = data.akeyless_csr.test_csr
		}
	`, keyPath)
	testutils.TesItemDataSource(t, providerFactories, config, "csr", []string{"data"})
}

func TestCertificateDataSource(t *testing.T) {
	key, cert := testutils.GenerateCertForTest(t, 2048)
	certificateName := "test-certificate-data"
	certificatePath := testPath(certificateName)
	testutils.CreateCertificate(t, certificatePath, cert, key)
	defer testutils.DeleteItem(t, certificatePath)
	config := fmt.Sprintf(`
		data "akeyless_certificate" "test_certificate" {
			name	= "%v"
		}

		output "certificate" {
			value     = data.akeyless_certificate.test_certificate
			sensitive = true
		}
	`, certificatePath)
	testutils.TesItemDataSource(t, providerFactories, config, "certificate", []string{"certificate_pem", "private_key_pem"})
}

func TestFolderResource(t *testing.T) {
	t.Parallel()
	folderEndName := "test_folder"
	folderName := testPath(folderEndName)
	config := fmt.Sprintf(`
		resource "akeyless_folder" "%v" {
			name 				= "%v"
			description 		= "aaaa"
			tags 				= ["t1", "t2"]
			delete_protection  	= "true"
		}
	`, folderEndName, folderName)
	configUpdate := fmt.Sprintf(`
		resource "akeyless_folder" "%v" {
			name 				= "%v"
			description 		= "bbbb"
			tags 				= ["t1", "t3"]
		}
	`, folderEndName, folderName)
	configUpdate2 := fmt.Sprintf(`
		resource "akeyless_folder" "%v" {
			name 				= "%v"
			delete_protection  	= "false"
		}
	`, folderEndName, folderName)
	testutils.TestFolderResource(t, providerFactories, folderName, config, configUpdate, configUpdate2)
}
