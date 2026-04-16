package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"
)

func TestTargetDataSourceLinkedTarget(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	parentTargetName := "target-db-for-linked-target"
	parentTargetPath := testPath(parentTargetName)
	createTarget(t, parentTargetPath)
	defer testutils.DeleteTarget(t, parentTargetPath)

	targetName := "target-linked-target"
	targetPath := testPath(targetName)
	targetDetailsType := "linked_target_details"

	expect := map[string]interface{}{
		"hosts":  "server1.com;my-server01,server2.com;my-server02",
		"parent": parentTargetPath,
	}

	createLinkedTarget(t, targetPath, expect)
	defer testutils.DeleteTarget(t, targetPath)

	config := fmt.Sprintf(`
		data "akeyless_target_details" "%v" {
			name = "%v"
		}
		output "target_details" {
			value = data.akeyless_target_details.%v.value
		}
	`, targetName, targetPath, targetName)

	testTargetDataSource(t, config, targetPath, targetDetailsType, expect)
}

func createTarget(t *testing.T, targetPath string) {
	client, token := testutils.PrepareClient(t)

	body := akeyless_api.CreateDBTarget{
		Name:   targetPath,
		Token:  &token,
		DbType: "mysql",
	}
	common.GetAkeylessPtr(&body.UserName, "user1")
	common.GetAkeylessPtr(&body.Pwd, "1234")
	common.GetAkeylessPtr(&body.Host, "127.0.0.1")
	common.GetAkeylessPtr(&body.Port, "5678")
	common.GetAkeylessPtr(&body.DbName, "abcd")

	_, resp, err := client.CreateDBTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create db target for test", resp, err))
}

func createLinkedTarget(t *testing.T, name string, details map[string]interface{}) {
	client, token := testutils.PrepareClient(t)

	body := akeyless_api.CreateLinkedTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Hosts, details["hosts"])
	common.GetAkeylessPtr(&body.ParentTargetName, details["parent"])

	_, resp, err := client.CreateLinkedTarget(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create linked target for test", resp, err))
}

func testTargetDataSource(t *testing.T, config, targetPath, targetType string, expect map[string]interface{}) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkTargetDetailsRemotely(targetPath, targetType, expect),
				),
			},
		},
	})
}

func checkTargetDetailsRemotely(path, targetType string, expect map[string]interface{}) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		targetDetails := s.Modules[0].Outputs["target_details"]
		if targetDetails == nil {
			return fmt.Errorf("target details not shown in terraform output")
		}

		value, ok := targetDetails.Value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("wrong value variable type")
		}

		valuePerType, ok := value[targetType]
		if !ok {
			return fmt.Errorf("wrong value target type")
		}

		details, ok := valuePerType.(string)
		if !ok {
			return fmt.Errorf("wrong details variable type")
		}

		var detailsMap map[string]interface{}
		err := json.Unmarshal([]byte(details), &detailsMap)
		if err != nil {
			return err
		}

		adjustResultAndInput(detailsMap, expect, targetType)

		eq := reflect.DeepEqual(detailsMap, expect)
		if !eq {
			return fmt.Errorf("value is not equal\nexpect: %v\nactual: %v", expect, value)
		}

		return nil
	}
}

func adjustResultAndInput(actual, expect map[string]interface{}, targetType string) error {
	if val, ok := actual["app_id"]; ok {
		if fVal, ok := val.(float64); ok {
			actual["app_id"] = int(fVal)
		}
	}

	if val, ok := expect["timeout"]; ok {
		dur, err := time.ParseDuration(val.(string))
		if err != nil {
			return err
		}
		expect["timeout"] = int(dur)
	}
	if val, ok := actual["timeout"]; ok {
		if fVal, ok := val.(float64); ok {
			actual["timeout"] = int(fVal)
		}
	}

	if targetType == "linked_target_details" {
		delete(expect, "parent")

		if h, ok := actual["hosts"].(string); ok && strings.HasPrefix(h, "map[") {
			inner := strings.TrimPrefix(strings.TrimSuffix(h, "]"), "map[")
			parts := strings.Fields(inner)
			pairs := make([]string, 0, len(parts))
			for _, p := range parts {
				kv := strings.SplitN(p, ":", 2)
				if len(kv) == 2 {
					pairs = append(pairs, kv[0]+";"+kv[1])
				}
			}
			sort.Strings(pairs)
			actual["hosts"] = strings.Join(pairs, ",")
		}
		if h, ok := expect["hosts"].(string); ok {
			parts := strings.Split(h, ",")
			sort.Strings(parts)
			expect["hosts"] = strings.Join(parts, ",")
		}
	}

	return nil
}
