package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRole() *schema.Resource {
	return &schema.Resource{
		Description:   "Role Resource",
		CreateContext: resourceRoleCreate,
		Read:          resourceRoleRead,
		Update:        resourceRoleUpdate,
		Delete:        resourceRoleDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRoleImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Role name",
			},
			"comment": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Comment about the role",
				Default:     "",
			},
			"assoc_auth_method": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Create an association between role and auth method",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"am_name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The auth method to associate",
						},
						"sub_claims": {
							Type:        schema.TypeMap,
							Optional:    true,
							Description: "key/val of sub claims, e.g group=admins,developers",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},
			"rules": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Set a rule to a role",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"capability": {
							Type:        schema.TypeSet,
							Required:    true,
							Description: "List of the approved/denied capabilities in the path options: [read, create, update, delete, list, deny]",
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"path": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The path the rule refers to",
						},
						"rule_type": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "item-rule, target-rule, role-rule, auth-method-rule",
							Default:     "item-rule",
						},
					},
				},
			},
			"audit_access": { // same as search-rule
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Allow this role to view audit logs. Currently only 'none', 'own' and 'all' values are supported, allowing associated auth methods to view audit logs produced by the same auth methods.",
			},
			"analytics_access": { // same as reports-rule
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Allow this role to view analytics. Currently only 'none', 'own' and 'all' values are supported, allowing associated auth methods to view reports produced by the same auth methods.",
			},
			"gw_analytics_access": { // same as gw-reports-rule
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Allow this role to view gw analytics. Currently only 'none', 'own' and 'all' values are supported, allowing associated auth methods to view reports produced by the same auth methods.",
			},
			"sra_reports_access": { // same as sra-reports-rule
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Allow this role to view SRA Clusters. Currently only 'none', 'own' and 'all' values are supported.",
			},
		},
	}
}

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (ret diag.Diagnostics) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token
	warn := diag.Diagnostics{}
	ok := true

	name := d.Get("name").(string)
	comment := d.Get("comment").(string)
	auditAccess := d.Get("audit_access").(string)
	analyticsAccess := d.Get("analytics_access").(string)
	gwAnalyticsAccess := d.Get("gw_analytics_access").(string)
	sraReportsAccess := d.Get("sra_reports_access").(string)

	var apiErr akeyless.GenericOpenAPIError
	body := akeyless.CreateRole{
		Name:    name,
		Comment: akeyless.PtrString(comment),
		Token:   &token,
	}
	common.GetAkeylessPtr(&body.AuditAccess, auditAccess)
	common.GetAkeylessPtr(&body.AnalyticsAccess, analyticsAccess)
	common.GetAkeylessPtr(&body.GwAnalyticsAccess, gwAnalyticsAccess)
	common.GetAkeylessPtr(&body.SraReportsAccess, sraReportsAccess)

	_, _, err := client.CreateRole(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return diag.Diagnostics{common.ErrorDiagnostics(fmt.Sprintf("can't create Role: %v", string(apiErr.Body())))}
		}
		return diag.Diagnostics{common.ErrorDiagnostics(fmt.Sprintf("can't create Role: %v", err))}
	}
	// defer func() {
	// 	if !ok {
	// 		deleteRole := akeyless.DeleteRole{
	// 			Name:  name,
	// 			Token: &token,
	// 		}

	// 		_, _, err = client.DeleteRole(ctx).Body(deleteRole).Execute()
	// 		if err != nil {
	// 			ret = diag.Diagnostics{common.ErrorDiagnostics(fmt.Sprintf("fatal error: role created with errors and failed to be deleted: %v", err))}
	// 		}
	// 	}
	// }()

	assocAuthMethod := d.Get("assoc_auth_method").([]interface{})
	err, ok = assocRoleAuthMethod(ctx, name, assocAuthMethod, m)
	if !ok {
		return diag.Diagnostics{common.ErrorDiagnostics(err.Error())}
	}

	roleRules := d.Get("rules").([]interface{})
	err, ok = setRoleRule(ctx, name, roleRules, m)
	if !ok {
		return diag.Diagnostics{common.ErrorDiagnostics(err.Error())}
	}

	d.SetId(name)

	return warn
}

func resourceRoleRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Id()
	body := akeyless.GetRole{
		Name:  name,
		Token: &token,
	}

	role, err := getRole(d, client, body)
	if err != nil {
		return err
	}

	if role.Rules.PathRules != nil {
		err = readRules(d, *role.Rules.PathRules)
		if err != nil {
			return err
		}
	}

	return nil
}

func resourceRoleUpdate(d *schema.ResourceData, m interface{}) (err error) {
	ok := true
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Get("name").(string)
	ctx := context.Background()

	body := akeyless.GetRole{
		Name:  name,
		Token: &token,
	}
	role, err := getRole(d, client, body)
	if err != nil {
		return err
	}

	assocAuthMethod := d.Get("assoc_auth_method").([]interface{})
	assocAuthMethodOldValues := saveAssocAuthMethodOldValues(role.RoleAuthMethodsAssoc)

	err, ok = deleteRoleAuthMethods(ctx, name, assocAuthMethod, role.RoleAuthMethodsAssoc, m)
	if !ok {
		return err
	}
	defer func() {
		if !ok {
			errInner, okInner := assocRoleAuthMethod(ctx, name, assocAuthMethodOldValues, m)
			if !okInner {
				err = fmt.Errorf("fatal error, can't restore role association after bad update: %v", errInner)
			}
		}
	}()

	err, ok = assocRoleAuthMethod(ctx, name, assocAuthMethod, m)
	if !ok {
		return err
	}
	defer func() {
		if !ok {
			err, _ = deleteRoleAuthMethods(ctx, name, assocAuthMethodOldValues, role.RoleAuthMethodsAssoc, m)
			if err != nil {
				err = fmt.Errorf("fatal error, can't delete new role association after bad update: %v", err)
			}
		}
	}()

	roleRules := d.Get("rules").([]interface{})
	roleRulesOldValues := saveRoleRuleOldValues(role.Rules.PathRules)

	err, ok = deleteRoleRules(ctx, name, role.Rules.PathRules, m)
	if !ok {
		return err
	}
	defer func() {
		if !ok {
			errInner, okInner := setRoleRule(ctx, name, roleRulesOldValues, m)
			if !okInner {
				err = fmt.Errorf("fatal error, can't restore role rules after bad update: %v", errInner)
			} else {
				err = nil
			}
		}
	}()

	err, ok = setRoleRule(ctx, name, roleRules, m)
	if !ok {
		return err
	}
	defer func() {
		if !ok {
			err, _ = deleteRoleRules(ctx, name, role.Rules.PathRules, m)
			if err != nil {
				err = fmt.Errorf("fatal error, can't delete new role rules after bad update: %v", err)
			}
		}
	}()

	err, ok = updateRoleAccessRules(d, m, ctx)
	if !ok {
		return fmt.Errorf("can't update role access rule: %v", err)
	}
	// on error, the defer with deleteRoleRules will delete these rules too

	d.SetId(name)

	return nil
}

func resourceRoleDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Id()

	body := akeyless.GetRole{
		Name:  name,
		Token: &token,
	}

	ctx := context.Background()
	role, err := getRole(d, client, body)
	if err != nil {
		return err
	}

	for _, v := range role.GetRoleAuthMethodsAssoc() {
		deleteRoleAssociation := akeyless.DeleteRoleAssociation{
			AssocId: *v.AssocId,
			Token:   &token,
		}
		_, res, err := client.DeleteRoleAssociation(ctx).Body(deleteRoleAssociation).Execute()
		if err != nil {
			var apiErr akeyless.GenericOpenAPIError
			if errors.As(err, &apiErr) {
				if res.StatusCode != http.StatusNotFound {
					return err
				}
			} else {
				return err
			}
		}
	}

	rules := role.GetRules()
	for _, v := range rules.GetPathRules() {
		deleteRoleRule := akeyless.DeleteRoleRule{
			RoleName: name,
			Path:     *v.Path,
			RuleType: v.Type,
			Token:    &token,
		}

		_, res, err := client.DeleteRoleRule(ctx).Body(deleteRoleRule).Execute()
		if err != nil {
			var apiErr akeyless.GenericOpenAPIError
			if errors.As(err, &apiErr) {
				if res.StatusCode != http.StatusNotFound {
					return err
				}
			} else {
				return err
			}
		}
	}

	deleteRole := akeyless.DeleteRole{
		Name:  name,
		Token: &token,
	}

	_, _, err = client.DeleteRole(ctx).Body(deleteRole).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceRoleImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Id()

	item := akeyless.GetRole{
		Name:  name,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GetRole(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", name)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func getRole(d *schema.ResourceData, client akeyless.V2ApiService, body akeyless.GetRole) (akeyless.Role, error) {
	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	role, res, err := client.GetRole(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The secret was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return akeyless.Role{}, nil
			}
			return akeyless.Role{}, fmt.Errorf("can't get Role value: %v", string(apiErr.Body()))
		}
		return akeyless.Role{}, fmt.Errorf("can't get Role value: %v", err)
	}
	return role, nil
}

func readRules(d *schema.ResourceData, rules []akeyless.PathRule) error {
	var err error

	var roleRules []interface{}
	for _, ruleSrc := range rules {

		if isAccessRule(*ruleSrc.Type) {
			err = setAccessRuleField(d, *ruleSrc.Type, *ruleSrc.Path)
			if err != nil {
				return err
			}
		} else {
			rolesDst := make(map[string]interface{})

			rolesDst["capability"] = *ruleSrc.Capabilities
			rolesDst["path"] = *ruleSrc.Path
			rolesDst["rule_type"] = *ruleSrc.Type

			roleRules = append(roleRules, rolesDst)
		}
	}

	err = d.Set("rules", roleRules)
	if err != nil {
		return err
	}

	return nil
}

func assocRoleAuthMethod(ctx context.Context, name string, assocAuthMethod []interface{}, m interface{}) (error, bool) {

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	for _, v := range assocAuthMethod {
		assoc := v.(map[string]interface{})
		authMethodName := assoc["am_name"].(string)
		subClaims := assoc["sub_claims"].(map[string]interface{})
		sc := make(map[string]string, len(subClaims))
		for k, v := range subClaims {
			sc[k] = v.(string)
		}

		var apiErr akeyless.GenericOpenAPIError
		asBody := akeyless.AssocRoleAuthMethod{
			RoleName:  name,
			AmName:    authMethodName,
			SubClaims: &sc,
			Token:     &token,
		}

		_, res, err := client.AssocRoleAuthMethod(ctx).Body(asBody).Execute()
		if err != nil {
			if errors.As(err, &apiErr) {
				if res.StatusCode != http.StatusConflict {
					err = fmt.Errorf("can't create association: %v", string(apiErr.Body()))
					return err, false
				}
			} else {
				err = fmt.Errorf("can't create association: %v", err)
				return err, false
			}
		}
	}
	return nil, true
}

func setRoleRule(ctx context.Context, name string, roleRules []interface{}, m interface{}) (error, bool) {
	var err error
	var warn error

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	for _, v := range roleRules {
		var apiErr akeyless.GenericOpenAPIError

		roles := v.(map[string]interface{})
		capability := getCapability(roles["capability"])
		path := roles["path"].(string)
		ruleType := roles["rule_type"].(string)
		if ruleType == "search-rule" || ruleType == "reports-rule" || ruleType == "gw-reports-rule" || ruleType == "sra_reports_access" {
			warnMsgToAppend := "Deprecated: rule types 'search-rule and reports-rule' are deprecated and will be removed, please use 'audit_access' or 'analytics_access' instead"
			warn = fmt.Errorf("%v. %v", warn, warnMsgToAppend)
		} else if ruleType != "item-rule" && ruleType != "role-rule" && ruleType != "target-rule" && ruleType != "auth-method-rule" {
			err = fmt.Errorf("wrong rule types: %v", string(apiErr.Body()))
			return err, false
		}

		setRoleRule := akeyless.SetRoleRule{
			RoleName:   name,
			Capability: capability,
			Path:       path,
			RuleType:   akeyless.PtrString(ruleType),
			Token:      &token,
		}

		_, _, err = client.SetRoleRule(ctx).Body(setRoleRule).Execute()
		if err != nil {
			if errors.As(err, &apiErr) {
				err = fmt.Errorf("can't set rules: %v", string(apiErr.Body()))
				return err, false
			}
			err = fmt.Errorf("can't set rules: %v", err)
			return err, false
		}
	}

	return warn, true
}

func getCapability(capability interface{}) []string {
	if capSlice, ok := capability.([]string); ok {
		return capSlice
	} else if capSet, ok := capability.(*schema.Set); ok {
		return common.ExpandStringList(capSet.List())
	}
	return nil
}

func updateRoleAccessRules(d *schema.ResourceData, m interface{}, ctx context.Context) (error, bool) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Get("name").(string)
	auditAccess := d.Get("audit_access").(string)
	analyticsAccess := d.Get("analytics_access").(string)
	gwAnalyticsAccess := d.Get("gw_analytics_access").(string)
	sraReportsAccess := d.Get("sra_reports_access").(string)

	updateBody := akeyless.UpdateRole{
		Name:              name,
		Token:             &token,
		AuditAccess:       akeyless.PtrString(auditAccess),
		AnalyticsAccess:   akeyless.PtrString(analyticsAccess),
		GwAnalyticsAccess: akeyless.PtrString(gwAnalyticsAccess),
		SraReportsAccess:  akeyless.PtrString(sraReportsAccess),
	}

	var apiErr akeyless.GenericOpenAPIError
	_, _, err := client.UpdateRole(ctx).Body(updateBody).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("%v", string(apiErr.Body())), false
		}
		return fmt.Errorf("%v", err), false
	}

	return nil, true
}

func saveAssocAuthMethodOldValues(assoc *[]akeyless.RoleAuthMethodAssociation) []interface{} {
	var assocAuthMethodOldValues []interface{}

	if assoc != nil {
		for _, val := range *assoc {
			assocMap := make(map[string]interface{})
			assocMap["am_name"] = *val.AuthMethodName
			subClaims := make(map[string]interface{})
			for key := range *val.AuthMethodSubClaims {
				subClaims[key] = strings.Join((*val.AuthMethodSubClaims)[key], ",")
			}
			assocMap["sub_claims"] = subClaims
			assocAuthMethodOldValues = append(assocAuthMethodOldValues, assocMap)
		}
	}

	return assocAuthMethodOldValues
}

func deleteRoleAuthMethods(ctx context.Context, name string, assocAuthMethod []interface{}, assocAuthMethodOldValues *[]akeyless.RoleAuthMethodAssociation, m interface{}) (error, bool) {

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	if assocAuthMethodOldValues != nil && assocAuthMethod != nil {
		for _, v := range *assocAuthMethodOldValues {
			var apiErr akeyless.GenericOpenAPIError
			association := akeyless.DeleteRoleAssociation{
				AssocId: *v.AssocId,
				Token:   &token,
			}
			_, res, err := client.DeleteRoleAssociation(ctx).Body(association).Execute()
			if err != nil {
				if errors.As(err, &apiErr) {
					if res.StatusCode != http.StatusNotFound {
						return fmt.Errorf("can't delete Role association: %v", string(apiErr.Body())), false
					}
				} else {
					return fmt.Errorf("can't delete Role association: %v", err), false
				}
			}
		}
	}
	return nil, true
}

func saveRoleRuleOldValues(roleRules *[]akeyless.PathRule) []interface{} {
	var roleRulesOldValues []interface{}

	if roleRules != nil {
		for _, val := range *roleRules {
			rulesMap := make(map[string]interface{})

			rulesMap["capability"] = *val.Capabilities
			rulesMap["path"] = *val.Path
			rulesMap["rule_type"] = *val.Type

			roleRulesOldValues = append(roleRulesOldValues, rulesMap)
		}
	}

	return roleRulesOldValues
}

func deleteRoleRules(ctx context.Context, name string, PathRules *[]akeyless.PathRule, m interface{}) (err error, ok bool) {

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	if PathRules != nil {
		for _, v := range *PathRules {
			var apiErr akeyless.GenericOpenAPIError
			rule := akeyless.DeleteRoleRule{
				RoleName: name,
				Path:     *v.Path,
				RuleType: v.Type,
				Token:    &token,
			}
			_, res, err := client.DeleteRoleRule(ctx).Body(rule).Execute()
			if err != nil {
				if errors.As(err, &apiErr) {
					if res.StatusCode != http.StatusNotFound {
						return fmt.Errorf("can't delete rule: %v", string(apiErr.Body())), false
					}
				} else {
					return fmt.Errorf("can't delete rule: %v", err), false
				}
			}
		}
	}

	return nil, true
}

func isAccessRule(roleType string) bool {
	return roleType == "search-rule" || roleType == "reports-rule" || roleType == "gw-reports-rule" || roleType == "sra-reports-rule"
}

func setAccessRuleField(d *schema.ResourceData, roleType, rolePath string) error {

	rolePath = convertPathName(rolePath)
	switch roleType {
	case "search-rule":
		return d.Set("audit_access", rolePath)
	case "reports-rule":
		return d.Set("analytics_access", rolePath)
	case "gw-reports-rule":
		return d.Set("gw_analytics_access", rolePath)
	case "sra-reports-rule":
		return d.Set("sra_reports_access", rolePath)
	default:
		return nil
	}
}

func convertPathName(rolePath string) string {
	switch rolePath {
	case "/*":
		return "all"
	case "/self":
		return "own"
	default:
		return ""
	}
}
