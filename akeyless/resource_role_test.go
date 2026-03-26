package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
)

const RULE_PATH = "/terraform-tests/*"

func TestRoleResourceBasic(t *testing.T) {
	rolePath := testPath("test_role_resource")
	deleteRole(rolePath)
	defer deleteRole(rolePath)

	config := fmt.Sprintf(`
		resource "akeyless_role" "test_role" {
			name 				= "%v"
			description 		= "aaaa"
			delete_protection 	= "true"
			audit_access 		= "all"
			analytics_access 	= "own"
		}
	`, rolePath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_role" "test_role" {
			name 				= "%v"
			description 		= "bbbb"
			delete_protection 	= "false"
			audit_access 		= "own"
			analytics_access 	= "all"
		}
	`, rolePath)

	var checkRoleDestroyed = func(s *terraform.State) error {
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		for _, rs := range s.RootModule().Resources {
			if rs.Type == "akeyless_role" {
				body := akeyless_api.GetRole{
					Name:  rs.Primary.ID,
					Token: &token,
				}
				_, res, err := client.GetRole(context.Background()).Body(body).Execute()
				if err == nil {
					return fmt.Errorf("role %s still exists", rs.Primary.ID)
				}
				if res != nil && res.StatusCode != 404 {
					return fmt.Errorf("role %s: unexpected status %d", rs.Primary.ID, res.StatusCode)
				}
			}
		}
		return nil
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkRoleDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_role.test_role", "description", "aaaa"),
					resource.TestCheckResourceAttr("akeyless_role.test_role", "delete_protection", "true"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_role.test_role", "description", "bbbb"),
					resource.TestCheckResourceAttr("akeyless_role.test_role", "delete_protection", "false"),
				),
			},
		},
	})
}

func TestRoleResourceUpdateRules(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath := testPath("test_am_resource")
	deleteRole(rolePath)
	defer deleteRole(rolePath)
	deleteAuthMethod(authMethodPath, "api_key")
	defer deleteAuthMethod(authMethodPath, "api_key")

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
					checkRoleExistsRemotely(t, rolePath, authMethodPath, 3),
				),
			},
			{
				Config: configAddRole,
				Check: resource.ComposeTestCheckFunc(
					checkAddRoleRemotely(t, rolePath, 4),
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
func TestRoleResourceRuleWithNoLeadingSlash(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath := testPath("test_am_resource")
	deleteRole(rolePath)
	defer deleteRole(rolePath)
	deleteAuthMethod(authMethodPath, "api_key")
	defer deleteAuthMethod(authMethodPath, "api_key")

	rulePath := "terraform-tests/*"

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
	`, authMethodPath, rolePath, authMethodPath, rulePath)

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
	`, authMethodPath, rolePath, authMethodPath, rulePath, rulePath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkRoleExistsRemotely(t, rolePath, authMethodPath, 3),
				),
			},
			{
				Config: configAddRole,
				Check: resource.ComposeTestCheckFunc(
					checkAddRoleRemotely(t, rolePath, 4),
				),
			},
		},
	})
}

func TestRoleResourceUpdateAssoc(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath := testPath("test_am_resource")
	deleteRole(rolePath)
	defer deleteRole(rolePath)
	deleteAuthMethod(authMethodPath, "api_key")
	defer deleteAuthMethod(authMethodPath, "api_key")

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
					checkRoleExistsRemotely(t, rolePath, authMethodPath, 3),
				),
			},
			{
				Config: configAddRole,
				Check: resource.ComposeTestCheckFunc(
					checkAddRoleRemotely(t, rolePath, 4),
				),
			},
			{
				Config: configUpdateRole,
				Check: resource.ComposeTestCheckFunc(
					checkUpdateRoleRemotely(t, rolePath, 3),
				),
			},
			{
				Config: configRemoveRole,
				Check: resource.ComposeTestCheckFunc(
					checkRemoveRoleRemotely(t, rolePath, 2),
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
	defer deleteRole(rolePath)
	deleteAuthMethod(authMethodPath1, "api_key")
	defer deleteAuthMethod(authMethodPath1, "api_key")
	deleteAuthMethod(authMethodPath2, "api_key")
	defer deleteAuthMethod(authMethodPath2, "api_key")

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
			audit_access 		= "all"
			  
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
					checkRoleExistsRemotely(t, rolePath, authMethodPath1, 2),
				),
			},
			{
				Config: configAddAssoc,
				Check: resource.ComposeTestCheckFunc(
					checkAddRoleRemotely(t, rolePath, 1),
				),
			},
			{
				Config: configRemoveRole,
				Check: resource.ComposeTestCheckFunc(
					checkRemoveRoleRemotely(t, rolePath, 2),
				),
			},
		},
	})
}

func TestRoleResourceAndAssocAuthMethod(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath := testPath("test_am_resource")
	deleteRole(rolePath)
	defer deleteRole(rolePath)
	deleteAuthMethod(authMethodPath, "api_key")
	defer deleteAuthMethod(authMethodPath, "api_key")

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
	skipIfNoGateway(t)
	t.Parallel()
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
	defer deleteRole(rolePath)

	amPath1 := testPath("test_am1")
	createTestAuthMethod(amPath1)
	defer deleteAuthMethod(amPath1, "api_key")

	amPath2 := testPath("test_am2")
	createTestAuthMethod(amPath2)
	defer deleteAuthMethod(amPath2, "api_key")

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
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		gsvBody := akeyless_api.GetRole{
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

		if common.IsCICDEnv() {
			rulesNum++
		}
		if rulesNum != len(rules.GetPathRules()) {
			fmt.Println("rulesNum:", res.GetRules())
			fmt.Println("len(rules.GetPathRules()):", rules.GetPathRules())
		}

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
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		gsvBody := akeyless_api.GetRole{
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
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		gsvBody := akeyless_api.GetRole{
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
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		gsvBody := akeyless_api.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		rules := res.GetRules()

		if common.IsCICDEnv() {
			rulesNum++
		}

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
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		gsvBody := akeyless_api.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, accnum, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		rules := res.GetRules()

		if common.IsCICDEnv() {
			rulesNum++
		}

		assert.Equal(t, rulesNum, len(rules.GetPathRules()))

		return nil
	}
}

func checkRemoveRoleRemotely(t *testing.T, roleName string, rulesNum int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		gsvBody := akeyless_api.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		rules := res.GetRules()

		if common.IsCICDEnv() {
			rulesNum++
		}

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

	gsvBody := akeyless_api.DeleteRole{
		Name:  path,
		Token: &token,
	}

	var apiErr akeyless_api.GenericOpenAPIError

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

	gsvBody := akeyless_api.CreateAuthMethod{
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

func deleteAuthMethod(path string, authMethodType string) error {
	p, err := getProviderMeta()
	if err != nil {
		panic(err)
	}

	client := p.client
	token := *p.token

	// Try to delete with the exact path first
	gsvBody := akeyless_api.AuthMethodDelete{
		Name:  path,
		Token: &token,
	}

	_, _, err = client.AuthMethodDelete(context.Background()).Body(gsvBody).Execute()
	if err != nil {
		// If 404 and path doesn't start with /, try with leading slash
		if strings.Contains(err.Error(), "404") && !strings.HasPrefix(path, "/") {
			pathWithSlash := "/" + path
			gsvBody.Name = pathWithSlash
			_, _, err2 := client.AuthMethodDelete(context.Background()).Body(gsvBody).Execute()
			if err2 == nil {
				fmt.Println("deleted auth method:", pathWithSlash)
				return nil
			}
			err = err2 // Use the new error for further processing
		}
	} else {
		// Deletion succeeded
		fmt.Println("deleted auth method:", path)
		return nil
	}

	if err != nil {
		// Check if error is due to delete protection
		errStr := err.Error()
		if strings.Contains(errStr, "delete protection") || strings.Contains(errStr, "delete_protection") {
			fmt.Println("delete protection enabled, removing protection and retrying...")

			// Update to remove delete protection based on auth method type
			switch authMethodType {
			case "api_key":
				updateBody := akeyless_api.AuthMethodUpdateApiKey{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateApiKey(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			case "aws_iam":
				updateBody := akeyless_api.AuthMethodUpdateAwsIam{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateAwsIam(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			case "azure_ad":
				updateBody := akeyless_api.AuthMethodUpdateAzureAD{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateAzureAD(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			case "cert":
				updateBody := akeyless_api.AuthMethodUpdateCert{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateCert(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			case "gcp":
				updateBody := akeyless_api.AuthMethodUpdateGcp{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateGcp(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			case "k8s":
				updateBody := akeyless_api.AuthMethodUpdateK8s{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateK8s(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			case "ldap":
				updateBody := akeyless_api.AuthMethodUpdateLdap{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateLdap(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			case "oauth2":
				updateBody := akeyless_api.AuthMethodUpdateOauth2{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateOauth2(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			case "oidc":
				updateBody := akeyless_api.AuthMethodUpdateOIDC{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateOIDC(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			case "saml":
				updateBody := akeyless_api.AuthMethodUpdateSAML{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateSAML(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			case "universal_identity":
				updateBody := akeyless_api.AuthMethodUpdateUniversalIdentity{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateUniversalIdentity(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			case "kerberos":
				updateBody := akeyless_api.AuthMethodUpdateKerberos{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateKerberos(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			case "oci":
				updateBody := akeyless_api.AuthMethodUpdateOCI{
					Name:             path,
					Token:            &token,
					DeleteProtection: akeyless_api.PtrString("false"),
				}
				_, _, updateErr := client.AuthMethodUpdateOCI(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					fmt.Println("error updating auth method:", updateErr)
					return err
				}
			}

			// Retry deletion
			_, _, retryErr := client.AuthMethodDelete(context.Background()).Body(gsvBody).Execute()
			if retryErr != nil {
				return retryErr
			}
			fmt.Println("deleted auth method:", path)
			return nil
		}

		return err
	}

	// Should not reach here
	return nil
}
