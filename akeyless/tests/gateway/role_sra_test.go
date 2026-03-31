package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestRoleResourceWithSraRule(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	rolePath := testPath("test_role_resource_sra_rule")
	testutils.DeleteRole(rolePath)

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
