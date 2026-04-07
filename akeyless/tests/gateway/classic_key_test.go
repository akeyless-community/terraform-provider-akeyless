package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
)

func TestClassicKey(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "test_classic_key"
	itemPath := testPath(name)

	certPem, certDer := testutils.GenerateCertForTestWithKey(t, 1024, itemPath)

	config := fmt.Sprintf(`
		resource "akeyless_classic_key" "%v" {
			name 		= "%v"
			alg 		= "RSA2048"
			generate_self_signed_certificate 	= true
			certificate_ttl 					= 60
			certificate_common_name 			= "cn1"
			certificate_organization 			= "org1"
			certificate_country 				= "cntry1"
			certificate_locality 				= "local1"
			certificate_province 				= "prov1"
			tags 		= ["aaaa", "bbbb"]
			certificate_format = "der"
			auto_rotate = "false"
			expiration_event_in = ["15"]
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_classic_key" "%v" {
			name 		= "%v"	
			alg 		= "RSA2048"
			generate_self_signed_certificate 	= true
			certificate_ttl 					= 60
			certificate_common_name 			= "cn1"
			certificate_organization 			= "org1"
			certificate_country 				= "cntry1"
			certificate_locality 				= "local1"
			certificate_province 				= "prov1"
			tags 		= ["cccc", "dddd"]
			description = "abcd"
			cert_file_data = "%v"
			certificate_format = "pem"
			auto_rotate = "true"
			rotation_interval = "9"
			rotation_event_in = ["4"]
			expiration_event_in = ["14"]
		}
	`, name, itemPath, certPem)

	configUpdate2 := fmt.Sprintf(`
		resource "akeyless_classic_key" "%v" {
			name 		= "%v"	
			alg 		= "RSA2048"
			generate_self_signed_certificate 	= true
			certificate_ttl 					= 60
			certificate_common_name 			= "cn1"
			certificate_organization 			= "org1"
			certificate_country 				= "cntry1"
			certificate_locality 				= "local1"
			certificate_province 				= "prov1"
			tags 		= ["cccc", "dddd"]
			description = "efgh"
			cert_file_data = "%v"
			certificate_format = "der"
			auto_rotate = "true"
			rotation_interval = "8"
			rotation_event_in = ["5"]
			expiration_event_in = ["11"]
		}
	`, name, itemPath, certDer)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate, configUpdate2)
}

func TestClassicGpgKey(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "test_classic_gpg_key"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_classic_key" "%v" {
			name 		= "%v"
			alg			= "GPG"
			gpg_alg 	= "RSA2048"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_classic_key" "%v" {
			name 		= "%v"	
			alg			= "GPG"
			gpg_alg 	= "RSA2048"
			description = "GPG"
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestClassicAESKey(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "test_classic_aes_key"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_classic_key" "%v" {
			name 		= "%v"
			alg			= "AES256GCM"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_classic_key" "%v" {
			name 		= "%v"	
			alg			= "AES256GCM"
			description = "AES"
		}
	`, name, itemPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}

func TestPkiResourceWithLocalGw(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	keyPath := testPath("test-dfc-for-pki-with-gw")
	testutils.CreateDfcKey(t, keyPath)
	defer testutils.DeleteItem(t, keyPath)

	name := "test-pki-resource-with-gw"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_pki_cert_issuer" "%v" {
			name 					= "%v"
			signer_key_name 		= "/%v"
			ttl                   	= "8760h"
			gw_cluster_url 			= "http://localhost:8081"
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
			enable_acme             = false
			expiration_event_in   	= ["1"]
			allowed_extra_extensions = "{\"1.2.3.4.5\":[\"value1\",\"value2\"],\"1.2.3.4.6\":[\"value3\",\"value4\"]}"
			allow_copy_ext_from_csr = true
			create_public_crl	 	= true
			create_private_crl	 	= true
			auto_renew			 	= true
			scheduled_renew			= 5
			description           	= "desc1"
			tags     			  	= ["t1", "t2"]
			delete_protection     	= "true"
		}
	`, name, itemPath, keyPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_pki_cert_issuer" "%v" {
			name 					= "%v"
			signer_key_name 		= "/%v"
			ttl                   	= "240h30m51s"
			gw_cluster_url 			= "http://localhost:8081"
			destination_path      	= "/terraform-tests"
			allowed_domains       	= "domain1,domain2"
			allowed_uri_sans      	= "uri_san1,uri_san2"
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
			enable_acme             = false
			expiration_event_in   	= []
			allowed_extra_extensions = "{\"1.2.3.4.5\":[\"value1\",\"value5\"]}"
			allow_copy_ext_from_csr = false
			create_public_crl	 	= false
			create_private_crl	 	= false
			auto_renew			 	= false
			scheduled_renew			= 6
			description           	= "desc2"
			tags     			  	= ["t1", "t3"]
		}
	`, name, itemPath, keyPath)

	testutils.TestItemResource(t, providerFactories, itemPath, config, configUpdate)
}
