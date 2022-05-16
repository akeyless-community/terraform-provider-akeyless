package akeyless

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
)

func TestOnlyRoleResourceCreate(t *testing.T) {
	rolePath := testPath("test_role_assoc")
	authMethodPath := testPath("path_auth_method")
	deleteRole(rolePath)
	deleteAuthMethod(authMethodPath)

	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "test_auth_method" {
			path 	= "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role" {
			name = "%v"
			assoc_auth_method {
				am_name = "%v"
			}
			depends_on = [
    			akeyless_auth_method.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  resource.ComposeTestCheckFunc(),
			},
		},
	})
}

func TestRoleWithAssocResourceUpdate(t *testing.T) {
	rolePath := testPath("test_role_assoc")
	authMethodPath := testPath("path_auth_method")
	deleteRole(rolePath)
	deleteAuthMethod(authMethodPath)
	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role_assoc" {
			name = "%v"
			assoc_auth_method {
				am_name = "%v"
				sub_claims = {
					"groups" = "admins,developers"  
				}
			}
			rules {
				capability = ["read"]
				path = "/terraform-tests/*"
				rule_type = "auth-method-rule"
			}
			audit_access = "all"
			  analytics_access = "all"
			  
			depends_on = [
    			akeyless_auth_method.auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath)

	configAddRole := fmt.Sprintf(`
		resource "akeyless_auth_method" "auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role_assoc" {
			name = "%v"
			assoc_auth_method {
				am_name = "%v"
				sub_claims = {
					"groups" = "admins,developers"
				}
			}
			rules {
				capability = ["read"]
				path = "/terraform-tests/*"
				rule_type = "auth-method-rule"
			}

			rules {
				capability = ["list"]
				path = "/terraform-tests/secrets/*"
				rule_type = "auth-method-rule"
			}
			audit_access = "all"
			  analytics_access = "all"
			  
			depends_on = [
    			akeyless_auth_method.auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath)

	configUpdateRole := fmt.Sprintf(`
		resource "akeyless_auth_method" "auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role_assoc" {
			name = "%v"
			assoc_auth_method {
				am_name = "%v"
				sub_claims = {
					"groups" = "admins,developers"
				}
			}
			rules {
				capability = ["read"]
				path = "/terraform-tests/*"
				rule_type = "auth-method-rule"
			}

			audit_access = "all"
			  analytics_access = "own"

			depends_on = [
    			akeyless_auth_method.auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath)

	configRemoveRole := fmt.Sprintf(`
		resource "akeyless_auth_method" "auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role_assoc" {
			name = "%v"
			assoc_auth_method {
				am_name = "%v"
				sub_claims = {
					"groups" = "admins,developers"
				}
			}
			rules {
				capability = ["read"]
				path = "/terraform-tests/*"
				rule_type = "auth-method-rule"
			}
			audit_access = "all"
			  analytics_access = "all"
			  
			depends_on = [
    			akeyless_auth_method.auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkRoleExistsRemotely(t, rolePath, authMethodPath),
				),
			},
			{
				Config: configAddRole,
				Check: resource.ComposeTestCheckFunc(
					checkAddRoleRemotely(t, rolePath),
				),
			},
			{
				Config: configUpdateRole,
				Check: resource.ComposeTestCheckFunc(
					checkUpdateRoleRemotely(t, rolePath),
				),
			},
			{
				Config: configRemoveRole,
				Check: resource.ComposeTestCheckFunc(
					checkRemoveRoleRemotely(t, rolePath),
				),
			},
		},
	})
}
func TestRoleWithAssocResourceUpdateDeleteAssoc(t *testing.T) {
	rolePath := testPath("test_role_assoc")
	authMethodPath := testPath("path_auth_method")
	deleteRole(rolePath)
	deleteAuthMethod(authMethodPath)
	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role_assoc" {
			name = "%v"
			assoc_auth_method {
				am_name = "%v"
				sub_claims = {
					"groups" = "admins,developers"  
				}
			}
			rules {
				capability = ["read"]
				path = "/terraform-tests/*"
				rule_type = "auth-method-rule"
			}
			audit_access = "all"
			  analytics_access = "all"
			  
			depends_on = [
    			akeyless_auth_method.auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath)

	configAddRole := fmt.Sprintf(`
		resource "akeyless_auth_method" "auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role_assoc" {
			name = "%v"
			assoc_auth_method {
				am_name = "%v"
				sub_claims = {
					"groups" = "admins,developers"
				}
			}
			rules {
				capability = ["read"]
				path = "/terraform-tests/*"
				rule_type = "auth-method-rule"
			}

			rules {
				capability = ["list"]
				path = "/terraform-tests/secrets/*"
				rule_type = "auth-method-rule"
			}
			audit_access = "all"
			  analytics_access = "all"
			  
			depends_on = [
    			akeyless_auth_method.auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath)

	configUpdateRole := fmt.Sprintf(`
		resource "akeyless_auth_method" "auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role_assoc" {
			name = "%v"
			rules {
				capability = ["read"]
				path = "/terraform-tests/*"
				rule_type = "auth-method-rule"
			}

			audit_access = "all"
			  analytics_access = "own"

			depends_on = [
    			akeyless_auth_method.auth_method,
  			]
		}
	`, authMethodPath, rolePath)

	configRemoveRole := fmt.Sprintf(`
		resource "akeyless_auth_method" "auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role_assoc" {
			name = "%v"
			assoc_auth_method {
				am_name = "%v"
				sub_claims = {
					"groups" = "admins,developers"
				}
			}
			rules {
				capability = ["read"]
				path = "/terraform-tests/*"
				rule_type = "auth-method-rule"
			}
			audit_access = "all"
			  analytics_access = "all"
			  
			depends_on = [
    			akeyless_auth_method.auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkRoleExistsRemotely(t, rolePath, authMethodPath),
				),
			},
			{
				Config: configAddRole,
				Check: resource.ComposeTestCheckFunc(
					checkAddRoleRemotely(t, rolePath),
				),
			},
			{
				Config: configUpdateRole,
				Check: resource.ComposeTestCheckFunc(
					checkUpdateRoleRemotelyNoAcc(t, rolePath),
				),
			},
			{
				Config: configRemoveRole,
				Check: resource.ComposeTestCheckFunc(
					checkRemoveRoleRemotely(t, rolePath),
				),
			},
		},
	})
}

func TestAssocRoleAuthMethodResource(t *testing.T) {
	rolePath := testPath("test_role_assoc")
	authMethodPath := testPath("path_auth_method")
	deleteRole(rolePath)
	deleteAuthMethod(authMethodPath)

	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "auth_method" {
			path = "%v"
			api_key {
			}
		}
		resource "akeyless_role" "test_role_assoc" {
			name = "%v"
			rules {
				capability = ["read"]
				path = "/terraform-tests/*"
				rule_type = "auth-method-rule"
			}
			audit_access = "all"
			analytics_access = "all"
		}
		resource "akeyless_associate_role_auth_method" "aa" {
			am_name = "%v"
			role_name = "%v"
			sub_claims = {
				"groups" = "admins,developers"  
			}
			case_sensitive = "true"
		depends_on = [
				akeyless_auth_method.auth_method,
				akeyless_role.test_role_assoc,
	 		]
		}
	`, authMethodPath, rolePath, authMethodPath, rolePath)

	configUpdateRole := fmt.Sprintf(`

		resource "akeyless_auth_method" "auth_method" {
			path = "%v"
			api_key {
			}
		}
		resource "akeyless_role" "test_role_assoc" {
			name = "%v"
			rules {
				capability = ["read"]
				path = "/terraform-tests/*"
				rule_type = "auth-method-rule"
			}
			audit_access = "all"
			analytics_access = "all"
		}
		
		resource "akeyless_associate_role_auth_method" "aa" {
			am_name = "%v"
			role_name = "%v"
			sub_claims = {
				"groups" = "admins" 
				"groups2" = "developers,hhh"  
			}
			case_sensitive = "true"

		depends_on = [
				akeyless_auth_method.auth_method,
				akeyless_role.test_role_assoc,
	 		]
		}
	`, authMethodPath, rolePath, authMethodPath, rolePath)
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkAssocExistsRemotely(t, rolePath, authMethodPath),
				),
			},
			{
				Config: configUpdateRole,
				Check: resource.ComposeTestCheckFunc(
					checkAssocExistsRemotely2(t, rolePath, authMethodPath),
				),
			},
		},
	})
}

func checkRoleExistsRemotely(t *testing.T, roleName, authMethodPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		association := res.GetRoleAuthMethodsAssoc()[0]
		assert.Equal(t, authMethodPath, *association.AuthMethodName, "auth method name mismatch")
		for k, v := range *association.AuthMethodSubClaims {
			assert.Equal(t, "groups", k)
			assert.Equal(t, strings.Split("admins,developers", ","), v)
		}

		rules := res.GetRules()
		assert.Equal(t, 4, len(rules.GetPathRules()))

		exists := false
		for _, r := range rules.GetPathRules() {
			if strings.Contains(r.GetPath(), "/terraform-tests/*") {
				exists = true
				assert.Equal(t, []string{"read"}, r.GetCapabilities())
				assert.Equal(t, "auth-method-rule", r.GetType())
			}
		}

		assert.True(t, exists)

		return nil
	}
}
func checkAssocExistsRemotely(t *testing.T, roleName, authMethodPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		association := res.GetRoleAuthMethodsAssoc()[0]
		assert.Equal(t, authMethodPath, *association.AuthMethodName, "auth method name mismatch")
		for k, v := range *association.AuthMethodSubClaims {
			assert.Equal(t, "groups", k)
			assert.Equal(t, strings.Split("admins,developers", ","), v)
		}
		return nil
	}
}

func checkAssocExistsRemotely2(t *testing.T, roleName, authMethodPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		association := res.GetRoleAuthMethodsAssoc()[0]
		assert.Equal(t, authMethodPath, *association.AuthMethodName, "auth method name mismatch")
		assert.Equal(t, int(2), len(*association.AuthMethodSubClaims), "auth method name mismatch")
		for k, v := range *association.AuthMethodSubClaims {
			if k == "groups" {
				assert.Equal(t, strings.Split("admins", ","), v)
			} else if k == "groups2" {
				assert.Equal(t, strings.Split("developers,hhh", ","), v)
			} else {
				t.Fail()
			}
		}

		return nil
	}
}

func checkAddRoleRemotely(t *testing.T, roleName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		rules := res.GetRules()
		assert.Equal(t, 3, len(rules.GetPathRules()))

		return nil
	}
}

func checkUpdateRoleRemotelyNoAcc(t *testing.T, roleName string) resource.TestCheckFunc {
	return checkUpdateRole(t, roleName, 0)
}
func checkUpdateRoleRemotely(t *testing.T, roleName string) resource.TestCheckFunc {
	return checkUpdateRole(t, roleName, 1)
}
func checkUpdateRole(t *testing.T, roleName string, accnum int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, accnum, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		rules := res.GetRules()
		assert.Equal(t, 4, len(rules.GetPathRules()))

		return nil
	}
}

func checkRemoveRoleRemotely(t *testing.T, roleName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(providerMeta).client
		token := *testAccProvider.Meta().(providerMeta).token

		gsvBody := akeyless.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		rules := res.GetRules()
		assert.Equal(t, 3, len(rules.GetPathRules()))

		return nil
	}
}

func deleteRole(path string) error {

	p, err := getProviderMeta()
	if err != nil {
		panic(err)
	}

	client := p.client
	token := *p.token

	gsvBody := akeyless.DeleteRole{
		Name:  path,
		Token: &token,
	}

	_, _, err = client.DeleteRole(context.Background()).Body(gsvBody).Execute()
	if err != nil {
		fmt.Println("error delete role:", err)
		return err
	}
	fmt.Println("deleted", path)
	return nil
}

func deleteAuthMethod(path string) error {
	p, err := getProviderMeta()
	if err != nil {
		panic(err)
	}

	client := p.client
	token := *p.token

	gsvBody := akeyless.DeleteAuthMethod{
		Name:  path,
		Token: &token,
	}

	_, _, err = client.DeleteAuthMethod(context.Background()).Body(gsvBody).Execute()
	if err != nil {
		fmt.Println("error delete auth method:", err)
		return err
	}
	fmt.Println("deleted", path)
	return nil
}
