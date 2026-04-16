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

func TestPolicyKeysResource(t *testing.T) {

	name := "test_policy_keys"
	policyPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_policy_keys" "%v" {
			path                       = "%v"
			allowed_algorithms         = ["RSA2048"]
			allowed_key_types          = ["dfc"]
			max_rotation_interval_days = 30
			object_types               = ["items"]
		}
	`, name, policyPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_policy_keys" "%v" {
			path                       = "%v"
			allowed_algorithms         = ["RSA2048", "AES128GCM"]
			max_rotation_interval_days = 60
			object_types               = ["items", "targets"]
		}
	`, name, policyPath)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkPolicyKeysDestroyed,
		Steps: []resource.TestStep{
			{Config: config},
			{Config: configUpdate},
		},
	})
}

var checkPolicyKeysDestroyed = func(s *terraform.State) error {
	client, token, err := testutils.GetClient()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "akeyless_policy_keys" {
			continue
		}

		body := akeyless_api.PoliciesGet{
			Id:    rs.Primary.ID,
			Token: &token,
		}
		_, res, err := client.PoliciesGet(context.Background()).Body(body).Execute()
		if err == nil {
			return fmt.Errorf("policy keys %s still exists", rs.Primary.ID)
		}
		if res != nil && res.StatusCode != 404 {
			return fmt.Errorf("policy keys %s: unexpected status %d", rs.Primary.ID, res.StatusCode)
		}
	}
	return nil
}
