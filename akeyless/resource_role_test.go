package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
)

const RULE_PATH = "/terraform-tests/*"

func TestRoleResourceBasic(t *testing.T) {
	rolePath := testPath("test_role_resource")
	deleteRole(rolePath)

	config := fmt.Sprintf(`
		resource "akeyless_role" "test_role" {
			name 		= "%v1"
			description = "aaaa"
		}
	`, rolePath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_role" "test_role" {
			name 		= "%v2"
			description = "bbbb"
		}
	`, rolePath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  resource.ComposeTestCheckFunc(),
			},
			{
				Config: configUpdate,
				Check:  resource.ComposeTestCheckFunc(),
			},
		},
	})
}

func TestRoleResourceUpdateRules(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath := testPath("test_am_resource")
	deleteRole(rolePath)
	deleteAuthMethod(authMethodPath)

	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "test_auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role" {
			name 	= "%v"
			assoc_auth_method {
				am_name 	= "%v"
				sub_claims 	= {
					"groups" = "admins,developers"  
				}
			}
			rules {
				capability 	= ["read"]
				path 		= "%v"
				rule_type 	= "auth-method-rule"
			}
			audit_access 		= "all"
			analytics_access 	= "own"
			
			depends_on = [
    			akeyless_auth_method.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath, RULE_PATH)

	configAddRole := fmt.Sprintf(`
		resource "akeyless_auth_method" "test_auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role" {
			name 	= "%v"
			assoc_auth_method {
				am_name 	= "%v"
				sub_claims 	= {
					"groups" = "admins,developers"
				}
			}
			rules {
				capability 	= ["read", "list"]
				path 		= "%v"
				rule_type 	= "auth-method-rule"
			}
			rules {
				capability 	= ["read", "list"]
				path 		= "%v"
				rule_type 	= "item-rule"
			}
			audit_access 		= "all"
			analytics_access 	= "all"
			  
			depends_on = [
    			akeyless_auth_method.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath, RULE_PATH, RULE_PATH)

	configUpdateRole := fmt.Sprintf(`
		resource "akeyless_auth_method" "test_auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role" {
			name = "%v"
			assoc_auth_method {
				am_name 	= "%v"
				sub_claims 	= {
					"groups" = "admins,developers"
				}
			}
			rules {
				capability 	= ["read"]
				path 		= "%v"
				rule_type 	= "auth-method-rule"
			}
			rules {
				capability 	= ["read", "create"]
				path 		= "%v"
				rule_type 	= "item-rule"
			}
			audit_access 		= "all"
			analytics_access 	= "all"

			depends_on = [
    			akeyless_auth_method.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath, RULE_PATH, RULE_PATH)

	configRemoveRole := config

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkRoleExistsRemotely(t, rolePath, authMethodPath, 4),
				),
			},
			{
				Config: configAddRole,
				Check: resource.ComposeTestCheckFunc(
					checkAddRoleRemotely(t, rolePath, 5),
				),
			},
			{
				Config: configUpdateRole,
				Check: resource.ComposeTestCheckFunc(
					checkUpdateRoleRemotely(t, rolePath, 5),
				),
			},
			{
				Config: configRemoveRole,
				Check: resource.ComposeTestCheckFunc(
					checkRemoveRoleRemotely(t, rolePath, 4),
				),
			},
		},
	})
}

func TestRoleResourceUpdateAssoc(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath := testPath("test_am_resource")
	deleteRole(rolePath)
	deleteAuthMethod(authMethodPath)

	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "test_auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role" {
			name = "%v"
			assoc_auth_method {
				am_name 	= "%v"
				sub_claims 	= {
					"groups" = "admins,developers"  
				}
				case_sensitive = "false"
			}
			rules {
				capability 	= ["read"]
				path 		= "%v"
				rule_type 	= "auth-method-rule"
			}
			audit_access 		= "all"
			analytics_access 	= "all"
			
			depends_on = [
    			akeyless_auth_method.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath, RULE_PATH)

	configAddRole := fmt.Sprintf(`
		resource "akeyless_auth_method" "test_auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role" {
			name = "%v"
			assoc_auth_method {
				am_name 	= "%v"
				sub_claims 	= {
					"groups" = "dogs,rats"
				}
			}
			rules {
				capability 	= ["read" , "list"]
				path 		= "%v"
				rule_type 	= "auth-method-rule"
			}
			rules {
				capability 	= ["read" , "list"]
				path 		= "%v"
				rule_type 	= "item-rule"
			}
			audit_access 		= "all"
			analytics_access 	= "all"
			  
			depends_on = [
    			akeyless_auth_method.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath, RULE_PATH, RULE_PATH)

	configUpdateRole := fmt.Sprintf(`
		resource "akeyless_auth_method" "test_auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role" {
			name = "%v"
			rules {
				capability 	= ["read"]
				path 		= "%v"
				rule_type 	= "auth-method-rule"
			}

			audit_access 		= "all"
			analytics_access 	= "own"

			depends_on = [
    			akeyless_auth_method.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, RULE_PATH)

	configRemoveRole := fmt.Sprintf(`
		resource "akeyless_auth_method" "test_auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role" {
			name = "%v"
			audit_access 		= "all"
			analytics_access 	= "own"

			depends_on = [
    			akeyless_auth_method.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkRoleExistsRemotely(t, rolePath, authMethodPath, 4),
				),
			},
			{
				Config: configAddRole,
				Check: resource.ComposeTestCheckFunc(
					checkAddRoleRemotely(t, rolePath, 5),
				),
			},
			{
				Config: configUpdateRole,
				Check: resource.ComposeTestCheckFunc(
					checkUpdateRoleRemotely(t, rolePath, 4),
				),
			},
			{
				Config: configRemoveRole,
				Check: resource.ComposeTestCheckFunc(
					checkRemoveRoleRemotely(t, rolePath, 3),
				),
			},
		},
	})
}

func TestRoleResourceAddAssoc(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath1 := testPath("test_am_resource1")
	authMethodPath2 := testPath("test_am_resource2")
	deleteRole(rolePath)
	deleteAuthMethod(authMethodPath1)
	deleteAuthMethod(authMethodPath2)

	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "test_auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role" {
			name = "%v"
			assoc_auth_method {
				am_name 	= "%v"
				sub_claims 	= {
					"groups" = "admins,developers"  
				}
				case_sensitive = "false"
			}
			rules {
				capability 	= ["read"]
				path 		= "%v"
				rule_type 	= "auth-method-rule"
			}
			audit_access 		= "all"
			
			depends_on = [
    			akeyless_auth_method.test_auth_method,
  			]
		}
	`, authMethodPath1, rolePath, authMethodPath1, RULE_PATH)

	configAddAssoc := fmt.Sprintf(`
		resource "akeyless_auth_method" "test_auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role" {
			name = "%v"
			assoc_auth_method {
				am_name 	= "%v"
				sub_claims 	= {
					"groups" = "dogs,rats"
				}
			}
			  
			depends_on = [
    			akeyless_auth_method.test_auth_method,
  			]
		}
	`, authMethodPath2, rolePath, authMethodPath2)

	configRemoveRole := config

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkRoleExistsRemotely(t, rolePath, authMethodPath1, 3),
				),
			},
			{
				Config: configAddAssoc,
				Check: resource.ComposeTestCheckFunc(
					checkAddRoleRemotely(t, rolePath, 2),
				),
			},
			{
				Config: configRemoveRole,
				Check: resource.ComposeTestCheckFunc(
					checkRemoveRoleRemotely(t, rolePath, 3),
				),
			},
		},
	})
}

func TestRoleResourceAndAssocAuthMethod(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath := testPath("test_am_resource")
	deleteRole(rolePath)
	deleteAuthMethod(authMethodPath)

	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "test_auth_method" {
			path = "%v"
			api_key {
			}
		}
		resource "akeyless_role" "test_role" {
			name = "%v"
			rules {
				capability 	= ["read"]
				path 		= "%v"
				rule_type 	= "auth-method-rule"
			}
			audit_access 		= "all"
			analytics_access 	= "all"
		}
		resource "akeyless_associate_role_auth_method" "aa" {
			am_name 	= "%v"
			role_name 	= "%v"
			sub_claims 	= {
				"groups" = "admins,developers"  
			}
			case_sensitive = "true"

		depends_on = [
				akeyless_auth_method.test_auth_method,
				akeyless_role.test_role,
	 		]
		}
	`, authMethodPath, rolePath, RULE_PATH, authMethodPath, rolePath)

	configUpdateRole := fmt.Sprintf(`

		resource "akeyless_auth_method" "test_auth_method" {
			path = "%v"
			api_key {
			}
		}
		resource "akeyless_role" "test_role" {
			name = "%v"
			rules {
				capability 	= ["read"]
				path 		= "%v"
				rule_type 	= "auth-method-rule"
			}
			audit_access 		= "all"
			analytics_access 	= "all"
		}
		
		resource "akeyless_associate_role_auth_method" "aa" {
			am_name 	= "%v"
			role_name 	= "%v"
			sub_claims 	= {
				"groups" 	= "admins" 
				"groups2" 	= "dogs,rats"  
			}
			case_sensitive = "true"

		depends_on = [
				akeyless_auth_method.test_auth_method,
				akeyless_role.test_role,
	 		]
		}
	`, authMethodPath, rolePath, RULE_PATH, authMethodPath, rolePath)
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

func TestRoleResourceWithSraRule(t *testing.T) {
	//todo need to fix this test
	t.Skip()
	rolePath := testPath("test_role_resource_sra_rule")
	deleteRole(rolePath)

	config := fmt.Sprintf(
		`resource "akeyless_role" "test_role1" {
	name = "%v"
	rules {
		capability 	= ["allow_access"]
		path 		= "%v"
		rule_type 	= "sra-rule"
	}
	audit_access 		= "all"
	analytics_access 	= "all"
}`, rolePath, rolePath)

	configUpdateRole := fmt.Sprintf(`
		resource "akeyless_role" "test_role1" {
		  name = "%v"
		  rules {
			capability  = ["allow_access", "request_access"]
			path        = "/*"
			rule_type   = "sra-rule"
		  }
		  audit_access        = "all"
		  analytics_access    = "none"
		  gw_analytics_access = "all"
		  sra_reports_access  = "own"
		}`, rolePath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
			},
			{
				Config: configUpdateRole,
			},
		},
	})
}

func TestRoleResourceWithFewAssocs(t *testing.T) {
	resourceName := "test_role_few_assocs"
	rolePath := testPath(resourceName)

	amPath1 := testPath("test_am1")
	createTestAuthMethod(amPath1)
	defer deleteAuthMethod(amPath1)

	amPath2 := testPath("test_am2")
	createTestAuthMethod(amPath2)
	defer deleteAuthMethod(amPath2)

	config := fmt.Sprintf(`
		resource "akeyless_role" "%v" {
			name = "%v"
			assoc_auth_method {
				am_name     = "%v"
				sub_claims  = {
					"groups"  = "admins1"  
				}
			}
			assoc_auth_method {
				am_name     = "%v"
				sub_claims  = {
					"groups"  = "admins2"  
				}
			}
	  	}
	  `, resourceName, rolePath, amPath1, amPath2)

	// switch assocs order
	config2 := fmt.Sprintf(`
	  	resource "akeyless_role" "%v" {
			name = "%v"
			assoc_auth_method {
				am_name     = "%v"
				sub_claims  = {
					"groups"  = "admins2"  
				}
			}
			assoc_auth_method {
				am_name     = "%v"
				sub_claims  = {
					"groups"  = "admins1"  
				}
			}
		}
	`, resourceName, rolePath, amPath2, amPath1)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
			},
			{
				Config: config2,
			},
		},
	})
}

func checkRoleExistsRemotely(t *testing.T, roleName, authMethodPath string, rulesNum int) resource.TestCheckFunc {
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
		assert.Equal(t, rulesNum, len(rules.GetPathRules()))

		exists := false
		for _, r := range rules.GetPathRules() {
			if strings.Contains(r.GetPath(), RULE_PATH) {
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
				assert.Equal(t, strings.Split("dogs,rats", ","), v)
			} else {
				t.Fail()
			}
		}

		return nil
	}
}

func checkAddRoleRemotely(t *testing.T, roleName string, rulesNum int) resource.TestCheckFunc {
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

		assert.Equal(t, rulesNum, len(rules.GetPathRules()))

		return nil
	}
}

func checkUpdateRoleRemotelyNoAcc(t *testing.T, roleName string, rulesNum int) resource.TestCheckFunc {
	return checkUpdateRole(t, roleName, 0, rulesNum)
}
func checkUpdateRoleRemotely(t *testing.T, roleName string, rulesNum int) resource.TestCheckFunc {
	return checkUpdateRole(t, roleName, 1, rulesNum)
}
func checkUpdateRole(t *testing.T, roleName string, accnum, rulesNum int) resource.TestCheckFunc {
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
		assert.Equal(t, rulesNum, len(rules.GetPathRules()))

		return nil
	}
}

func checkRemoveRoleRemotely(t *testing.T, roleName string, rulesNum int) resource.TestCheckFunc {
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
		assert.Equal(t, rulesNum, len(rules.GetPathRules()))

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

	var apiErr akeyless.GenericOpenAPIError

	_, res, err := client.DeleteRole(context.Background()).Body(gsvBody).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode != http.StatusNotFound {
				return fmt.Errorf("can't delete role: %v", string(apiErr.Body()))
			}
		} else {
			return fmt.Errorf("can't delete role: %v", err)
		}
	}
	fmt.Println("deleted", path)
	return nil
}

func createTestAuthMethod(path string) error {
	p, err := getProviderMeta()
	if err != nil {
		panic(err)
	}

	client := p.client
	token := *p.token

	gsvBody := akeyless.CreateAuthMethod{
		Name:  path,
		Token: &token,
	}

	_, _, err = client.CreateAuthMethod(context.Background()).Body(gsvBody).Execute()
	if err != nil {
		fmt.Println("error create auth method:", err)
		return err
	}
	fmt.Println("created auth method:", path)
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
	fmt.Println("deleted auth method:", path)
	return nil
}
