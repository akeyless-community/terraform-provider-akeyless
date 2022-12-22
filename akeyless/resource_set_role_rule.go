// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcesetRoleRule() *schema.Resource {
	return &schema.Resource{
		Description: "Set Role Rule resource",
		Create:      resourcesetRoleRuleCreate,
		Read:        resourcesetRoleRuleRead,
		Update:      resourcesetRoleRuleUpdate,
		Delete:      resourcesetRoleRuleDelete,
		Importer: &schema.ResourceImporter{
			State: resourcesetRoleRuleImport,
		},
		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The role name to be updated",
			},
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path the rule refers to",
			},
			"capability": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "List of the approved/denied capabilities in the path options: [read, create, update, delete, list, deny]",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"rule_type": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "item-rule, target-rule, role-rule, auth-method-rule",
				Default:     "item-rule",
			},
		},
	}
}

func resourcesetRoleRuleCreate(d *schema.ResourceData, m interface{}) error {

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	roleName := d.Get("role_name").(string)
	path := d.Get("path").(string)
	capabilitySet := d.Get("capability").(*schema.Set)
	capability := common.ExpandStringList(capabilitySet.List())
	ruleType := d.Get("rule_type").(string)

	body := akeyless.SetRoleRule{
		RoleName:   roleName,
		Path:       path,
		Capability: capability,
		Token:      &token,
	}
	common.GetAkeylessPtr(&body.RuleType, ruleType)

	_, _, err := client.SetRoleRule(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(roleName)

	return nil
}

func resourcesetRoleRuleRead(d *schema.ResourceData, m interface{}) error {

	roleName := d.Get("role_name").(string)

	id := d.Id()

	role, err := getRole(d, roleName, m)
	if err != nil {
		return err
	}
	if role.RoleName != nil {
		err = d.Set("role_name", *role.RoleName)
		if err != nil {
			return err
		}
	}

	pathExpect := d.Get("path").(string)
	capabilitySet := d.Get("capability").(*schema.Set)
	capabilityExpect := common.ExpandStringList(capabilitySet.List())
	ruleTypeExpect := d.Get("rule_type").(string)

	d.Set("capability", []string{})
	d.Set("path", "")
	d.Set("rule_type", "")

	if role.Rules != nil && role.Rules.PathRules != nil {
		rules := *role.Rules.PathRules
		for _, rule := range rules {
			if areListsEqualInAnyOrder(*rule.Capabilities, capabilityExpect) && *rule.Path == pathExpect && *rule.Type == ruleTypeExpect {
				if rule.Capabilities != nil {
					err = d.Set("capability", *rule.Capabilities)
					if err != nil {
						return err
					}
				}
				if rule.Path != nil {
					err = d.Set("path", *rule.Path)
					if err != nil {
						return err
					}
				}
				if rule.Type != nil {
					err = d.Set("rule_type", *rule.Type)
					if err != nil {
						return err
					}
				}
				break
			}
		}
	}

	d.SetId(id)

	return nil
}

func resourcesetRoleRuleUpdate(d *schema.ResourceData, m interface{}) error {

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	roleName := d.Get("role_name").(string)
	path := d.Get("path").(string)
	capabilitySet := d.Get("capability").(*schema.Set)
	capability := common.ExpandStringList(capabilitySet.List())
	ruleType := d.Get("rule_type").(string)

	body := akeyless.SetRoleRule{
		RoleName:   roleName,
		Path:       path,
		Capability: capability,
		Token:      &token,
	}
	common.GetAkeylessPtr(&body.RuleType, ruleType)

	_, _, err := client.SetRoleRule(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(roleName)

	return nil
}

func resourcesetRoleRuleDelete(d *schema.ResourceData, m interface{}) error {

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteRoleRule{
		Token:    &token,
		RoleName: path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteRoleRule(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourcesetRoleRuleImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	roleName := d.Get("role_name").(string)

	id := d.Id()

	role, err := getRole(d, roleName, m)
	if err != nil {
		return nil, err
	}

	if role.RoleName != nil {
		err = d.Set("role_name", *role.RoleName)
		if err != nil {
			return nil, err
		}
	}

	pathExpect := d.Get("path").(string)
	capabilitySet := d.Get("capability").(*schema.Set)
	capabilityExpect := common.ExpandStringList(capabilitySet.List())
	ruleTypeExpect := d.Get("rule_type").(string)

	if role.Rules != nil && role.Rules.PathRules != nil {
		rules := *role.Rules.PathRules
		for _, rule := range rules {
			if areListsEqualInAnyOrder(*rule.Capabilities, capabilityExpect) && *rule.Path == pathExpect && *rule.Type == ruleTypeExpect {
				if *rule.Capabilities != nil {
					err = d.Set("capability", *rule.Capabilities)
					if err != nil {
						return nil, err
					}
				}
				if *rule.Path != "" {
					err = d.Set("path", *rule.Path)
					if err != nil {
						return nil, err
					}
				}
				if *rule.Type != "" {
					err = d.Set("rule_type", *rule.Type)
					if err != nil {
						return nil, err
					}
				}

				d.SetId(id)
				return []*schema.ResourceData{d}, nil
			}
		}
	}

	d.Set("capability", []string{})
	d.Set("path", "")
	d.Set("rule_type", "")
	d.SetId("")
	return nil, fmt.Errorf("role id: %v. requested rule was not found", id)
}

// lists may be equal but in different order. it is considered equal too.
func areListsEqualInAnyOrder(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	// create a map of string -> int
	diff := make(map[string]int, len(x))
	for _, _x := range x {
		// 0 value for int is 0, so just increment a counter for the string
		diff[_x] += 1
	}
	for _, _y := range y {
		// If the string _y is not in diff bail out early
		if _, ok := diff[_y]; !ok {
			return false
		}
		diff[_y] -= 1
		if diff[_y] == 0 {
			delete(diff, _y)
		}
	}
	return len(diff) == 0
}
