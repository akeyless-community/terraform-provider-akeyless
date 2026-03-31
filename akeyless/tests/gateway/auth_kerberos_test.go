package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAuthMethodKerberosResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	name := "test_auth_method_kerberos"
	path := testPath("auth_method_kerberos")
	testutils.DeleteAuthMethod(path, "kerberos")

	krb5ConfData := "dGVzdC1rcmI1LWNvbmY="
	keytabData := "BQIAAAAA"

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

	krb5ConfDataUpdated := "dGVzdC1rcmI1LWNvbmYtdXBkYXRlZA=="
	keytabDataUpdated := "BQIAAAAA"

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
					testutils.CheckMethodExistsRemotely(path),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckMethodExistsRemotely(path),
				),
			},
		},
	})
}
