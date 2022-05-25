// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"

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

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GetRole{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GetRole(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}
	if rOut.RoleName != nil {
		err = d.Set("role_name", *rOut.RoleName)
		if err != nil {
			return err
		}
	}

	if rOut.Rules != nil && rOut.Rules.PathRules != nil {
		rules := *rOut.Rules.PathRules

		pathExp := d.Get("path").(string)
		capabilitySet := d.Get("capability").(*schema.Set)
		capabilityExp := common.ExpandStringList(capabilitySet.List())
		ruleTypeExp := d.Get("rule_type").(string)

		var ruleCap []string
		var rulePath string
		var ruleType string

		for _, rule := range rules {
			if reflect.DeepEqual(*rule.Capabilities, capabilityExp) && *rule.Path == pathExp && *rule.Type == ruleTypeExp {
				ruleCap = *rule.Capabilities
				rulePath = *rule.Path
				ruleType = *rule.Type
				break
			}
		}

		if ruleCap != nil {
			err = d.Set("capability", ruleCap)
			if err != nil {
				return err
			}
		}
		if rulePath != "" {
			err = d.Set("path", rulePath)
			if err != nil {
				return err
			}
		}
		if ruleType != "" {
			err = d.Set("rule_type", ruleType)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

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
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GetRole{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GetRole(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
