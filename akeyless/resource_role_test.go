package akeyless

import (
	"context"
	"fmt"
	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestOnlyRoleResourceCreate(t *testing.T) {
	rolePath := testPath("test_role_assoc")
	authMethodPath := testPath("path_auth_method")
	config := fmt.Sprintf(`
		resource "akeyless_auth_method" "test_auth_method" {
			path = "%v"
			api_key {
			}
		}

		resource "akeyless_role" "test_role" {
			name = "%v"
			assoc_auth_method {
				am_name = "%v"
			}
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

func checkUpdateRoleRemotely(t *testing.T, roleName string) resource.TestCheckFunc {
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
