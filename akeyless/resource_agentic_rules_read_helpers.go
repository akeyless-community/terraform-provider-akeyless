package akeyless

import (
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func setAgenticRuleList(d *schema.ResourceData, fieldName string, rules []akeyless_api.AgenticRule) error {
	if len(rules) == 0 {
		return nil
	}

	values := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.Name == nil || rule.Rule == nil {
			continue
		}
		values = append(values, fmt.Sprintf("name=%s,rule=%s", *rule.Name, *rule.Rule))
	}

	if len(values) == 0 {
		return nil
	}

	return d.Set(fieldName, values)
}

func setAgenticRulesReadFields(d *schema.ResourceData, agenticRules *akeyless_api.AgenticRules) error {
	if agenticRules == nil {
		return nil
	}

	if err := setAgenticRuleList(d, "input_rule", agenticRules.GetInputRules()); err != nil {
		return err
	}
	if err := setAgenticRuleList(d, "output_rule", agenticRules.GetOutputRules()); err != nil {
		return err
	}

	return nil
}
