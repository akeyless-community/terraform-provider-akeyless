package no_gateway

import (
	"context"
	"fmt"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const RULE_PATH = "/terraform-tests/*"

func TestRoleResourceBasic(t *testing.T) {
	rolePath := testPath("test_role_resource")
	testutils.DeleteRole(rolePath)
	defer testutils.DeleteRole(rolePath)

	config := fmt.Sprintf(`
		resource "akeyless_role" "test_role" {
			name 				= "%v"
			description 		= "aaaa"
			audit_access 		= "scoped"
			analytics_access 	= "own"
			event_center_access = "all"
			isi_access 			= "all"
		}
	`, rolePath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_role" "test_role" {
			name 				= "%v"
			description 		= "bbbb"
			audit_access 		= "all"
			analytics_access 	= "all"
			event_center_access = "own"
			isi_access 			= "scoped"
		}
	`, rolePath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_role.test_role", "description", "aaaa"),
					resource.TestCheckResourceAttr("akeyless_role.test_role", "isi_access", "all"),
					testutils.CheckRoleRulesRemotely(t, rolePath, []testutils.ExpectedRule{
						{Type: "search-rule", Path: "/scoped", Capabilities: []string{"read"}},
						{Type: "reports-rule", Path: "/self", Capabilities: []string{"read"}},
						{Type: "event-rule", Path: "/*", Capabilities: []string{"read"}},
						{Type: "isi-rule", Path: "/*", Capabilities: []string{"read"}},
					}),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_role.test_role", "description", "bbbb"),
					resource.TestCheckResourceAttr("akeyless_role.test_role", "isi_access", "scoped"),
					testutils.CheckRoleRulesRemotely(t, rolePath, []testutils.ExpectedRule{
						{Type: "search-rule", Path: "/*", Capabilities: []string{"read"}},
						{Type: "reports-rule", Path: "/*", Capabilities: []string{"read"}},
						{Type: "event-rule", Path: "/self", Capabilities: []string{"read"}},
						{Type: "isi-rule", Path: "/scoped", Capabilities: []string{"read"}},
					}),
				),
			},
		},
	})
}

func TestRoleDeleteProtection(t *testing.T) {
	rolePath := testPath("test_role_resource")
	testutils.DeleteRole(rolePath)
	defer testutils.DeleteRole(rolePath)

	config := fmt.Sprintf(`
		resource "akeyless_role" "test_role" {
			name 				= "%v"
			delete_protection 	= "true"
		}
	`, rolePath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_role" "test_role" {
			name 				= "%v"
			delete_protection 	= "false"
		}
	`, rolePath)

	var checkRoleDestroyed = func(s *terraform.State) error {
		client, token, err := testutils.GetClient()
		if err != nil {
			return err
		}
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
					resource.TestCheckResourceAttr("akeyless_role.test_role", "delete_protection", "true"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_role.test_role", "delete_protection", "false"),
				),
			},
		},
	})
}

func TestRoleResourceUpdateRules(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath := testPath("test_am_resource")
	testutils.DeleteRole(rolePath)
	defer testutils.DeleteRole(rolePath)
	testutils.DeleteAuthMethod(authMethodPath, "api_key")
	defer testutils.DeleteAuthMethod(authMethodPath, "api_key")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
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
    			akeyless_auth_method_api_key.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath, RULE_PATH)

	configAddRole := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
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
    			akeyless_auth_method_api_key.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath, RULE_PATH, RULE_PATH)

	configUpdateRole := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
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
    			akeyless_auth_method_api_key.test_auth_method,
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
					testutils.CheckRoleExistsRemotely(t, rolePath, authMethodPath, 3),
				),
			},
			{
				Config: configAddRole,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckAddRoleRemotely(t, rolePath, 4),
				),
			},
			{
				Config: configUpdateRole,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckUpdateRoleRemotely(t, rolePath, 4),
				),
			},
			{
				Config: configRemoveRole,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckRemoveRoleRemotely(t, rolePath, 3),
				),
			},
		},
	})
}
func TestRoleResourceRuleWithNoLeadingSlash(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath := testPath("test_am_resource")
	testutils.DeleteRole(rolePath)
	defer testutils.DeleteRole(rolePath)
	testutils.DeleteAuthMethod(authMethodPath, "api_key")
	defer testutils.DeleteAuthMethod(authMethodPath, "api_key")

	rulePath := "terraform-tests/*"

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
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
    			akeyless_auth_method_api_key.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath, rulePath)

	configAddRole := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
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
    			akeyless_auth_method_api_key.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath, rulePath, rulePath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckRoleExistsRemotely(t, rolePath, authMethodPath, 3),
				),
			},
			{
				Config: configAddRole,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckAddRoleRemotely(t, rolePath, 4),
				),
			},
		},
	})
}

func TestRoleResourceUpdateAssoc(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath := testPath("test_am_resource")
	testutils.DeleteRole(rolePath)
	defer testutils.DeleteRole(rolePath)
	testutils.DeleteAuthMethod(authMethodPath, "api_key")
	defer testutils.DeleteAuthMethod(authMethodPath, "api_key")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
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
    			akeyless_auth_method_api_key.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath, RULE_PATH)

	configAddRole := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
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
    			akeyless_auth_method_api_key.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, authMethodPath, RULE_PATH, RULE_PATH)

	configUpdateRole := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
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
    			akeyless_auth_method_api_key.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath, RULE_PATH)

	configRemoveRole := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
		}

		resource "akeyless_role" "test_role" {
			name = "%v"
			audit_access 		= "all"
			analytics_access 	= "own"

			depends_on = [
    			akeyless_auth_method_api_key.test_auth_method,
  			]
		}
	`, authMethodPath, rolePath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckRoleExistsRemotely(t, rolePath, authMethodPath, 3),
				),
			},
			{
				Config: configAddRole,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckAddRoleRemotely(t, rolePath, 4),
				),
			},
			{
				Config: configUpdateRole,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckUpdateRoleRemotely(t, rolePath, 3),
				),
			},
			{
				Config: configRemoveRole,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckRemoveRoleRemotely(t, rolePath, 2),
				),
			},
		},
	})
}

func TestRoleResourceAddAssoc(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath1 := testPath("test_am_resource1")
	authMethodPath2 := testPath("test_am_resource2")
	testutils.DeleteRole(rolePath)
	defer testutils.DeleteRole(rolePath)
	testutils.DeleteAuthMethod(authMethodPath1, "api_key")
	defer testutils.DeleteAuthMethod(authMethodPath1, "api_key")
	testutils.DeleteAuthMethod(authMethodPath2, "api_key")
	defer testutils.DeleteAuthMethod(authMethodPath2, "api_key")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
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
    			akeyless_auth_method_api_key.test_auth_method,
  			]
		}
	`, authMethodPath1, rolePath, authMethodPath1, RULE_PATH)

	configAddAssoc := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
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
    			akeyless_auth_method_api_key.test_auth_method,
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
					testutils.CheckRoleExistsRemotely(t, rolePath, authMethodPath1, 2),
				),
			},
			{
				Config: configAddAssoc,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckAddRoleRemotely(t, rolePath, 1),
				),
			},
			{
				Config: configRemoveRole,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckRemoveRoleRemotely(t, rolePath, 2),
				),
			},
		},
	})
}

func TestRoleResourceAndAssocAuthMethod(t *testing.T) {
	rolePath := testPath("test_role_resource")
	authMethodPath := testPath("test_am_resource")
	testutils.DeleteRole(rolePath)
	defer testutils.DeleteRole(rolePath)
	testutils.DeleteAuthMethod(authMethodPath, "api_key")
	defer testutils.DeleteAuthMethod(authMethodPath, "api_key")

	config := fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
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
				akeyless_auth_method_api_key.test_auth_method,
				akeyless_role.test_role,
	 		]
		}
	`, authMethodPath, rolePath, RULE_PATH, authMethodPath, rolePath)

	configUpdateRole := fmt.Sprintf(`

		resource "akeyless_auth_method_api_key" "test_auth_method" {
			name = "%v"
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
				akeyless_auth_method_api_key.test_auth_method,
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
					testutils.CheckAssocExistsRemotely(t, rolePath, authMethodPath),
				),
			},
			{
				Config: configUpdateRole,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckAssocExistsRemotely2(t, rolePath, authMethodPath),
				),
			},
		},
	})
}

// TestAssocRoleAmForceNewOnRoleNameChange verifies that changing role_name
// (ForceNew) destroys and recreates the association, including when one role
// path has a leading slash and the other does not.
func TestAssocRoleAmForceNewOnRoleNameChange(t *testing.T) {
	authMethodPath := testPath("test_am_assoc_force_new")
	role1Path := "/" + testPath("test_role1_with_slash")
	role2Path := testPath("test_role2_no_slash")

	testutils.DeleteRole(role1Path)
	testutils.DeleteRole(role2Path)
	testutils.DeleteAuthMethod(authMethodPath, "api_key")
	defer testutils.DeleteRole(role1Path)
	defer testutils.DeleteRole(role2Path)
	defer testutils.DeleteAuthMethod(authMethodPath, "api_key")

	configForRole := func(assocRolePath string) string {
		return fmt.Sprintf(`
		resource "akeyless_auth_method_api_key" "am" {
			name = "%v"
		}
		resource "akeyless_role" "role1" {
			name = "%v"
			rules {
				capability = ["read"]
				path       = "%v"
				rule_type  = "item-rule"
			}
		}
		resource "akeyless_role" "role2" {
			name = "%v"
			rules {
				capability = ["read"]
				path       = "%v"
				rule_type  = "item-rule"
			}
		}
		resource "akeyless_associate_role_auth_method" "assoc" {
			am_name   = akeyless_auth_method_api_key.am.name
			role_name = "%v"
			sub_claims = {
				"groups" = "admins"
			}
			depends_on = [
				akeyless_auth_method_api_key.am,
				akeyless_role.role1,
				akeyless_role.role2,
			]
		}
	`, authMethodPath, role1Path, RULE_PATH, role2Path, RULE_PATH, assocRolePath)
	}

	var assocIDAfterRole1 string

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: configForRole(role1Path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_associate_role_auth_method.assoc", "role_name", role1Path),
					testutils.CheckAssocExistsOnRole(t, role1Path, authMethodPath),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["akeyless_associate_role_auth_method.assoc"]
						if !ok {
							return fmt.Errorf("assoc resource not found in state")
						}
						assocIDAfterRole1 = rs.Primary.ID
						if assocIDAfterRole1 == "" {
							return fmt.Errorf("assoc id is empty after create")
						}
						return nil
					},
				),
			},
			{
				Config: configForRole(role2Path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_associate_role_auth_method.assoc", "role_name", role2Path),
					testutils.CheckAssocExistsOnRole(t, role2Path, authMethodPath),
					testutils.CheckAssocAbsentOnRole(t, role1Path),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["akeyless_associate_role_auth_method.assoc"]
						if !ok {
							return fmt.Errorf("assoc resource not found in state")
						}
						if rs.Primary.ID == "" {
							return fmt.Errorf("assoc id is empty after recreate")
						}
						if rs.Primary.ID == assocIDAfterRole1 {
							return fmt.Errorf("expected destroy+create (new assoc id), got same id %s", assocIDAfterRole1)
						}
						return nil
					},
				),
			},
		},
	})
}

func TestRoleResourceWithFewAssocs(t *testing.T) {
	resourceName := "test_role_few_assocs"
	rolePath := testPath(resourceName)
	defer testutils.DeleteRole(rolePath)

	amPath1 := testPath("test_am1")
	testutils.CreateTestAuthMethod(amPath1)
	defer testutils.DeleteAuthMethod(amPath1, "api_key")

	amPath2 := testPath("test_am2")
	testutils.CreateTestAuthMethod(amPath2)
	defer testutils.DeleteAuthMethod(amPath2, "api_key")

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
