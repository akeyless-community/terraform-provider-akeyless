package akeyless

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"log"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRole() *schema.Resource {
	return &schema.Resource{
		Description:   "Role Resource",
		CreateContext: resourceRoleCreate,
		Read:          resourceRoleRead,
		UpdateContext: resourceRoleUpdate,
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
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"assoc_auth_method": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Create an association between role and auth method",
				Deprecated:  "please use resource 'akeyless_associate_role_auth_method'",
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
						"case_sensitive": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Treat sub claims as case-sensitive",
							Default:     "true",
						},
						"access_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The access ID of the auth method",
						},
						"assoc_id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The association ID",
						},
					},
				},
			},
			"rules": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Set a rule to a role",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"capability": {
							Type:        schema.TypeSet,
							Required:    true,
							Description: "List of the approved/denied capabilities in the path options: [read, create, update, delete, list, deny] for sra-rule type: [allow_access, request_access, justify_access_only, approval_authority, upload_files, download_files]",
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
							Description: "item-rule, target-rule, role-rule, auth-method-rule, sra-rule",
							Default:     "item-rule",
						},
					},
				},
				Set: rulesHashFunction,
			},
			"restricted_rules": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"capability": {
							Type:     schema.TypeSet,
							Computed: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"path": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"rule_type": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
			"audit_access": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Allow this role to view audit logs. Currently only 'none', 'own' and 'all' values are supported, allowing associated auth methods to view audit logs produced by the same auth methods.",
			},
			"analytics_access": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Allow this role to view analytics. Currently only 'none', 'own' and 'all' values are supported, allowing associated auth methods to view reports produced by the same auth methods.",
			},
			"gw_analytics_access": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Allow this role to view gw analytics. Currently only 'none', 'own' and 'all' values are supported, allowing associated auth methods to view reports produced by the same auth methods.",
			},
			"sra_reports_access": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Allow this role to view SRA Clusters. Currently only 'none', 'own' and 'all' values are supported.",
			},
			"usage_reports_access": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Allow this role to view Usage reports. Currently only 'none' and 'all' values are supported.",
			},
			"event_center_access": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Allow this role to view Event Center. Currently only 'none', 'own' and 'all' values are supported.",
			},
			"event_forwarders_access": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Allow this role to manage Event Forwarders. Currently only 'none' and 'all' values are supported.",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this role, [true/false]",
				Default:     "false",
			},
		},
	}
}

// rulesHashFunction is used to generate a unique hash for a set of rules where leading slash is ensured for path.
func rulesHashFunction(v interface{}) int {
	m, ok := v.(map[string]interface{})
	if !ok {
		return 0
	}

	normalizedPath := common.EnsureLeadingSlash(m["path"].(string))

	hashString := fmt.Sprintf("%s-%s-%s",
		normalizedPath,
		m["rule_type"].(string),
		strings.Join(common.ExpandStringList(m["capability"].(*schema.Set).List()), ","),
	)

	return schema.HashString(hashString)
}

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (ret diag.Diagnostics) {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	warn := diag.Diagnostics{}
	ok := true

	name := d.Get("name").(string)
	description := d.Get("description").(string)
	auditAccess := d.Get("audit_access").(string)
	analyticsAccess := d.Get("analytics_access").(string)
	gwAnalyticsAccess := d.Get("gw_analytics_access").(string)
	sraReportsAccess := d.Get("sra_reports_access").(string)
	usageReportsAccess := d.Get("usage_reports_access").(string)
	eventCenterAccess := d.Get("event_center_access").(string)
	eventForwardersAccess := d.Get("event_forwarders_access").(string)
	deleteProtection := d.Get("delete_protection").(string)

	var apiErr akeyless_api.GenericOpenAPIError
	body := akeyless_api.CreateRole{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.AuditAccess, auditAccess)
	common.GetAkeylessPtr(&body.AnalyticsAccess, analyticsAccess)
	common.GetAkeylessPtr(&body.GwAnalyticsAccess, gwAnalyticsAccess)
	common.GetAkeylessPtr(&body.SraReportsAccess, sraReportsAccess)
	common.GetAkeylessPtr(&body.UsageReportsAccess, usageReportsAccess)
	common.GetAkeylessPtr(&body.EventCenterAccess, eventCenterAccess)
	common.GetAkeylessPtr(&body.EventForwardersAccess, eventForwardersAccess)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.CreateRole(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return diag.Diagnostics{common.ErrorDiagnostics(fmt.Sprintf("can't create Role: %v", string(apiErr.Body())))}
		}
		return diag.Diagnostics{common.ErrorDiagnostics(fmt.Sprintf("can't create Role: %v", err))}
	}
	defer func() {
		if !ok {
			errInner := resourceRoleDelete(d, m)
			if err != nil {
				ret = diag.Diagnostics{common.ErrorDiagnostics(fmt.Sprintf("fatal error: role created with errors and failed to be deleted: %v. delete error: %v", err, errInner))}
			}
		}
	}()

	// rules that created by admin of this account, and can't be removed (usually "deny" rules).
	err = initRestrictedRules(d, name, m)
	if err != nil {
		ok = false
		return diag.Diagnostics{common.ErrorDiagnostics(err.Error())}
	}

	assocsSet := d.Get("assoc_auth_method").(*schema.Set)
	assocAuthMethod := assocsSet.List()
	err, ok = addRoleAssocs(ctx, name, assocAuthMethod, m)
	if !ok {
		return diag.Diagnostics{common.ErrorDiagnostics(err.Error())}
	}

	rulesSet := d.Get("rules").(*schema.Set)
	roleRules := rulesSet.List()
	err, ok = addRoleRules(ctx, name, roleRules, m)
	if !ok {
		return diag.Diagnostics{common.ErrorDiagnostics(err.Error())}
	}

	d.SetId(name)

	return warn
}

func extractRestrictedRules(d *schema.ResourceData) []map[string]any {

	restrictedRules := make([]map[string]any, 0)

	restrictedRulesSet := d.Get("restricted_rules").(*schema.Set)
	restrictedRulesI := restrictedRulesSet.List()

	for _, restrictedRuleI := range restrictedRulesI {
		rule := restrictedRuleI.(map[string]any)
		restrictedRules = append(restrictedRules, rule)
	}

	return restrictedRules
}

func setRestrictedRules(d *schema.ResourceData, restrictedRules []map[string]any) error {
	rulesList := make([]interface{}, 0)
	for _, rule := range restrictedRules {
		rulesList = append(rulesList, rule)
	}
	return d.Set("restricted_rules", rulesList)
}

func initRestrictedRules(d *schema.ResourceData, name string, m any) error {

	var restrictedRules []map[string]any

	role, err := getRole(d, name, m)
	if err != nil {
		return fmt.Errorf("can't get old role: %w", err)
	}

	rules := role.Rules
	if rules == nil {
		return nil
	}

	for _, ruleSrc := range rules.PathRules {
		rule := make(map[string]any)
		rule["path"] = *ruleSrc.Path
		rule["rule_type"] = *ruleSrc.Type
		rule["capability"] = ruleSrc.Capabilities
		restrictedRules = append(restrictedRules, rule)
	}

	return setRestrictedRules(d, restrictedRules)
}

func resourceRoleRead(d *schema.ResourceData, m interface{}) error {
	name := d.Id()

	role, err := getRole(d, name, m)
	if err != nil {
		return err
	}

	if role.RoleAuthMethodsAssoc != nil {
		assocsSet := d.Get("assoc_auth_method").(*schema.Set)
		if len(assocsSet.List()) != 0 {
			err := readAuthMethodsAssoc(d, role.RoleAuthMethodsAssoc)
			if err != nil {
				return err
			}
		}
	}

	if role.Rules != nil {
		if role.Rules.PathRules != nil {
			rulesSet := d.Get("rules").(*schema.Set)
			if len(rulesSet.List()) != 0 {
				err := readRules(d, role.Rules.PathRules)
				if err != nil {
					return err
				}
			}
		}
	}

	if role.DeleteProtection != nil {
		err = d.Set("delete_protection", strconv.FormatBool(*role.DeleteProtection))
		if err != nil {
			return err
		}
	}

	return nil
}

func resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	cleanEmptyAssocs(d)

	ok := true

	name := d.Get("name").(string)
	//ctx := context.Background()

	role, err := getRole(d, name, m)
	if err != nil {
		return diag.FromErr(err)
	}

	assocsSet := d.Get("assoc_auth_method").(*schema.Set)
	assocAuthMethodNewValues := assocsSet.List()
	if len(assocAuthMethodNewValues) > 0 {
		assocAuthMethodOldValues := extractAssocValues(role.RoleAuthMethodsAssoc)

		assocsToAdd, assosToUpdateNew := extractAssocsToCreateAndUpdate(assocAuthMethodNewValues, assocAuthMethodOldValues)
		assocsToDelete, assocToRewrite := extractAssocsToCreateAndUpdate(assocAuthMethodOldValues, assocAuthMethodNewValues)

		err, ok = assocRoleAuthMethod(ctx, name, assocsToDelete, assocsToAdd, assosToUpdateNew, m)
		if !ok {
			return diag.FromErr(err)
		}
		defer func() {
			if !ok {
				err, _ = assocRoleAuthMethod(ctx, name, assocsToAdd, assocsToDelete, assocToRewrite, m)
				if err != nil {
					err = fmt.Errorf("fatal error, can't delete new role association after bad update: %v", err)
				}
			}
		}()
	}

	rules := role.Rules
	if rules == nil {
		return nil
	}

	rulesSet := d.Get("rules").(*schema.Set)
	roleRulesNewValues := rulesSet.List()

	roleRulesOldValues := extractRoleRuleOldValues(rules.PathRules)

	rulesToAdd := extractRulesToSet(d, roleRulesNewValues, roleRulesOldValues)
	rulesToDelete := extractRulesToSet(d, roleRulesOldValues, roleRulesNewValues)

	// TODO remove after debugging- ASM-13468
	if v, _ := strconv.ParseBool(os.Getenv("DEBUG_ROLE_RULES")); v {
		tflog.Debug(ctx, fmt.Sprintf("existing_role_rules: %v", roleRulesOldValues))
		tflog.Debug(ctx, fmt.Sprintf("requested_role_rules: %v", roleRulesNewValues))
	}

	err, ok = setRoleRules(ctx, name, rulesToDelete, rulesToAdd, m)
	defer func() {
		if !ok {
			err, _ := setRoleRules(ctx, name, rulesToAdd, rulesToDelete, m)
			if err != nil {
				log.Fatal(fmt.Printf("fatal error, can't delete new role rules after bad update: %v", err))
			}
		}
	}()
	if !ok {
		return diag.FromErr(err)
	}

	accessRulesNewValues := getNewAccessRules(d)
	accessRulesOldValues := saveRoleAccessRuleOldValues(rules.PathRules)
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(string)

	err, ok = updateRoleAccessRules(ctx, name, description, deleteProtection, accessRulesNewValues, m)
	if !ok {
		errInner, okInner := updateRoleAccessRules(ctx, name, description, deleteProtection, accessRulesOldValues, m)
		if !okInner {
			err = fmt.Errorf("fatal error, can't restore role access rules after bad update: %v", errInner)
		}

		return diag.FromErr(fmt.Errorf("can't update role access rule: %v", err))
	}

	d.SetId(name)

	return nil
}

func resourceRoleDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Id()

	deleteRole := akeyless_api.DeleteRole{
		Name:  name,
		Token: &token,
	}

	var apiErr akeyless_api.GenericOpenAPIError
	_, res, err := client.DeleteRole(ctx).Body(deleteRole).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode != http.StatusNotFound {
				return fmt.Errorf("can't delete role: %v", string(apiErr.Body()))
			}
		} else {
			return fmt.Errorf("can't delete role: %v", err)
		}
	}

	return nil
}

func resourceRoleImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	name := d.Id()

	role, err := getRole(d, name, m)
	if err != nil {
		return nil, err
	}

	rules := role.Rules
	if rules == nil {
		// ok - role with no rules
		return nil, nil
	}

	if rules.PathRules == nil {
		return nil, nil
	}

	err = readRules(d, rules.PathRules)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", name)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func getRole(d *schema.ResourceData, name string, m interface{}) (*akeyless_api.Role, error) {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	body := akeyless_api.GetRole{
		Name:  name,
		Token: &token,
	}
	role, res, err := client.GetRole(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The secret was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return &akeyless_api.Role{}, nil
			}
			return &akeyless_api.Role{}, fmt.Errorf("can't get Role value: %v", string(apiErr.Body()))
		}
		return &akeyless_api.Role{}, fmt.Errorf("can't get Role value: %v", err)
	}
	return role, nil
}

func readAuthMethodsAssoc(d *schema.ResourceData, authMethodsAssoc []akeyless_api.RoleAuthMethodAssociation) error {

	roleAuthMethodsAssoc := extractAssocValues(authMethodsAssoc)

	err := d.Set("assoc_auth_method", roleAuthMethodsAssoc)
	if err != nil {
		return err
	}
	return nil
}

func readRules(d *schema.ResourceData, rules []akeyless_api.PathRule) error {
	var err error
	var roleRules []interface{}

	for _, ruleSrc := range rules {
		if isAccessRule(*ruleSrc.Type) {
			err = setAccessRuleField(d, *ruleSrc.Type, *ruleSrc.Path)
			if err != nil {
				return err
			}
		} else {
			isRestrictedRule := false
			restrictedRules := extractRestrictedRules(d)
			for _, restrictedRule := range restrictedRules {
				if *ruleSrc.Type == restrictedRule["rule_type"] &&
					*ruleSrc.Path == restrictedRule["path"] {
					isRestrictedRule = true
					break
				}
			}
			if !isRestrictedRule {
				rolesDst := make(map[string]interface{})

				capabilities := ruleSrc.Capabilities
				if *ruleSrc.Type == "sra-rule" {
					capabilities = convertSraCapabilities(capabilities)
				}

				rolesDst["capability"] = capabilities
				rolesDst["path"] = *ruleSrc.Path
				rolesDst["rule_type"] = *ruleSrc.Type
				roleRules = append(roleRules, rolesDst)
			}
		}
	}

	err = d.Set("rules", roleRules)
	if err != nil {
		return err
	}

	return nil
}

func convertSraCapabilities(capabilities []string) []string {
	newCapabilities := make([]string, len(capabilities))
	for i, capability := range capabilities {
		switch capability {
		case "sra_transparently_connect":
			newCapabilities[i] = "allow_access"
		case "sra_request_for_access":
			newCapabilities[i] = "request_access"
		case "sra_require_justification":
			newCapabilities[i] = "justify_access_only"
		case "sra_approval_authority":
			newCapabilities[i] = "approval_authority"
		case "sra_upload_files":
			newCapabilities[i] = "upload_files"
		case "sra_download_files":
			newCapabilities[i] = "download_files"
		}
	}
	return newCapabilities
}

func extractAssocsToCreateAndUpdate(newAssocs, oldAssocs []interface{}) ([]interface{}, []interface{}) {
	var toAdd, toUpdate []interface{}

	for _, newAssocInterface := range newAssocs {
		assocExists := false
		newAssoc := newAssocInterface.(map[string]interface{})
		newSubClaims := newAssoc["sub_claims"].(map[string]interface{})

		for _, oldAssocInterface := range oldAssocs {
			oldAssoc := oldAssocInterface.(map[string]interface{})
			oldSubClaims := oldAssoc["sub_claims"].(map[string]interface{})

			if newAssoc["am_name"].(string) == oldAssoc["am_name"].(string) {
				assocExists = true
				if !reflect.DeepEqual(newSubClaims, oldSubClaims) {
					assocNewMap := make(map[string]interface{})
					if oldAssoc["assoc_id"] != nil {
						assocNewMap["assoc_id"] = oldAssoc["assoc_id"]
					} else {
						assocNewMap["assoc_id"] = newAssoc["assoc_id"] // for delete on error case
					}
					assocNewMap["am_name"] = newAssoc["am_name"]
					assocNewMap["sub_claims"] = newAssoc["sub_claims"].(map[string]interface{})
					if newAssoc["case_sensitive"] != nil {
						assocNewMap["case_sensitive"] = newAssoc["case_sensitive"]
					} else {
						assocNewMap["case_sensitive"] = ""
					}
					toUpdate = append(toUpdate, assocNewMap)
				}
				break
			}
		}
		if !assocExists {
			toAdd = append(toAdd, newAssoc)
		}
	}

	return toAdd, toUpdate
}

func extractRulesToSet(d *schema.ResourceData, newRules, oldRules []any) []any {
	var toSet []any

	for _, newRuleI := range newRules {
		newRule := newRuleI.(map[string]any)

		if isAccessRule(newRule["rule_type"].(string)) {
			continue // set only regular rules
		}
		if isRestrictedRule(d, newRule) {
			continue // restricted rules can't be removed
		}
		if isRuleExistsInOldRules(newRule, oldRules) {
			continue // rule already exists - redundant to add it
		}

		toSet = append(toSet, newRule)
	}

	return toSet
}

// check if a given rule is restricted (can't be removed/updated)
func isRestrictedRule(d *schema.ResourceData, rule map[string]any) bool {
	restrictedRules := extractRestrictedRules(d)
	for _, restrictedRule := range restrictedRules {
		if rule["rule_type"] == restrictedRule["rule_type"] &&
			rule["path"] == restrictedRule["path"] {
			return true
		}
	}
	return false
}

// check if a given rule is equal to another rule (same path, type, and capabilities)
func isRuleExistsInOldRules(newRule map[string]any, oldRules []interface{}) bool {
	for _, oldRuleI := range oldRules {
		oldRule := oldRuleI.(map[string]any)
		if isRulesEqual(newRule, oldRule) {
			return true
		}
	}
	return false
}

func assocRoleAuthMethod(ctx context.Context, name string, assocAuthMethodToDelete, assocAuthMethodToAdd, assocAuthMethodToUpdate []interface{}, m interface{}) (error, bool) {
	var err error
	var ok bool

	err, ok = deleteRoleAssocs(ctx, assocAuthMethodToDelete, m)
	if !ok {
		return err, ok
	}

	err, ok = addRoleAssocs(ctx, name, assocAuthMethodToAdd, m)
	if !ok {
		return err, ok
	}

	err, ok = updateRoleAssocs(ctx, assocAuthMethodToUpdate, m)
	if !ok {
		return err, ok
	}

	return nil, true
}

func deleteRoleAssocs(ctx context.Context, assocs []interface{}, m interface{}) (error, bool) {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	for _, v := range assocs {
		var apiErr akeyless_api.GenericOpenAPIError
		association := akeyless_api.DeleteRoleAssociation{
			AssocId: v.(map[string]interface{})["assoc_id"].(string),
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

	return nil, true
}

func addRoleAssocs(ctx context.Context, name string, assocAuthMethod []interface{}, m interface{}) (error, bool) {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	for _, v := range assocAuthMethod {
		assoc := v.(map[string]interface{})
		authMethodName := assoc["am_name"].(string)
		subClaims := assoc["sub_claims"].(map[string]interface{})
		caseSensitive := assoc["case_sensitive"].(string)
		sc := make(map[string]string, len(subClaims))
		for k, v := range subClaims {
			sc[k] = v.(string)
		}

		var apiErr akeyless_api.GenericOpenAPIError
		asBody := akeyless_api.AssocRoleAuthMethod{
			RoleName:      name,
			AmName:        authMethodName,
			SubClaims:     &sc,
			CaseSensitive: &caseSensitive,
			Token:         &token,
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

func updateRoleAssocs(ctx context.Context, assocAuthMethods []interface{}, m interface{}) (error, bool) {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	for _, v := range assocAuthMethods {
		assoc := v.(map[string]interface{})
		assocId := assoc["assoc_id"].(string)
		subClaims := assoc["sub_claims"].(map[string]interface{})
		caseSensitive := assoc["case_sensitive"].(string)
		sc := make(map[string]string, len(subClaims))
		for k, v := range subClaims {
			sc[k] = v.(string)
		}

		var apiErr akeyless_api.GenericOpenAPIError
		asBody := akeyless_api.UpdateAssoc{
			AssocId:       assocId,
			SubClaims:     &sc,
			Token:         &token,
			CaseSensitive: &caseSensitive,
		}

		_, res, err := client.UpdateAssoc(ctx).Body(asBody).Execute()
		if err != nil {
			if errors.As(err, &apiErr) {
				if res.StatusCode != http.StatusConflict {
					err = fmt.Errorf("can't update association: %v", string(apiErr.Body()))
					return err, false
				}
			} else {
				err = fmt.Errorf("can't update association: %v", err)
				return err, false
			}
		}
	}
	return nil, true
}

func setRoleRules(ctx context.Context, name string, rulesToDelete, rulesToAdd []interface{}, m interface{}) (error, bool) {
	var err error
	var ok bool

	err, ok = deleteRoleRules(ctx, name, rulesToDelete, m)
	if !ok {
		return err, ok
	}

	err, ok = addRoleRules(ctx, name, rulesToAdd, m)
	if !ok {
		return err, ok
	}

	return nil, true
}

func deleteRoleRules(ctx context.Context, name string, rules []interface{}, m interface{}) (err error, ok bool) {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	for _, v := range rules {
		ruleMap := v.(map[string]interface{})
		var apiErr akeyless_api.GenericOpenAPIError
		rule := akeyless_api.DeleteRoleRule{
			RoleName: name,
			Path:     ruleMap["path"].(string),
			RuleType: akeyless_api.PtrString(ruleMap["rule_type"].(string)),
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

	return nil, true
}

func addRoleRules(ctx context.Context, name string, roleRules []interface{}, m interface{}) (error, bool) {
	var warn error

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	for _, v := range roleRules {
		roles := v.(map[string]interface{})
		capability := getCapability(roles["capability"])
		path := roles["path"].(string)
		ruleType := roles["rule_type"].(string)
		if ruleType == "search-rule" || ruleType == "reports-rule" {
			warnMsgToAppend := "Deprecated: rule types 'search-rule and reports-rule' are deprecated and will be removed, please use 'audit_access' or 'analytics_access' instead"
			warn = fmt.Errorf("%v. %v", warn, warnMsgToAppend)
		} else if !isValidRuleType(ruleType) {
			return fmt.Errorf("wrong rule types"), false
		}

		var apiErr akeyless_api.GenericOpenAPIError
		setRoleRule := akeyless_api.SetRoleRule{
			RoleName:   name,
			Capability: capability,
			Path:       path,
			RuleType:   akeyless_api.PtrString(ruleType),
			Token:      &token,
		}

		_, _, err := client.SetRoleRule(ctx).Body(setRoleRule).Execute()
		if err != nil {
			if errors.As(err, &apiErr) {
				return fmt.Errorf("can't set rules: %v", string(apiErr.Body())), false
			}
			return fmt.Errorf("can't set rules: %v", err), false
		}
	}

	return warn, true
}

func getNewAccessRules(d *schema.ResourceData) []interface{} {
	var accessRules []interface{}

	auditAccess := d.Get("audit_access").(string)
	if auditAccess != "" {
		path := convertPathNameOpposite(auditAccess)
		auditAccessMap := map[string]interface{}{"capability": "read", "path": path, "rule_type": "search-rule"}
		accessRules = append(accessRules, auditAccessMap)
	}

	analyticsAccess := d.Get("analytics_access").(string)
	if analyticsAccess != "" {
		path := convertPathNameOpposite(analyticsAccess)
		analyticsAccessMap := map[string]interface{}{"capability": "read", "path": path, "rule_type": "reports-rule"}
		accessRules = append(accessRules, analyticsAccessMap)
	}

	gwAnalyticsAccess := d.Get("gw_analytics_access").(string)
	if gwAnalyticsAccess != "" {
		path := convertPathNameOpposite(gwAnalyticsAccess)
		gwAnalyticsAccessMap := map[string]interface{}{"capability": "read", "path": path, "rule_type": "gw-reports-rule"}
		accessRules = append(accessRules, gwAnalyticsAccessMap)
	}

	sraReportsAccess := d.Get("sra_reports_access").(string)
	if sraReportsAccess != "" {
		path := convertPathNameOpposite(sraReportsAccess)
		sraReportsAccessMap := map[string]interface{}{"capability": "read", "path": path, "rule_type": "sra-reports-rule"}
		accessRules = append(accessRules, sraReportsAccessMap)
	}

	usageReportsAccess := d.Get("usage_reports_access").(string)
	if usageReportsAccess != "" {
		path := convertPathNameOpposite(usageReportsAccess)
		usageReportsAccessMap := map[string]interface{}{"capability": "read", "path": path, "rule_type": "usage-reports-rule"}
		accessRules = append(accessRules, usageReportsAccessMap)
	}

	eventCenterAccess := d.Get("event_center_access").(string)
	if eventCenterAccess != "" {
		path := convertPathNameOpposite(eventCenterAccess)
		eventCenterAccessMap := map[string]interface{}{"capability": "read", "path": path, "rule_type": "event-rule"}
		accessRules = append(accessRules, eventCenterAccessMap)
	}

	eventForwardersAccess := d.Get("event_forwarders_access").(string)
	if eventForwardersAccess != "" {
		path := convertPathNameOpposite(eventForwardersAccess)
		eventForwardersAccessMap := map[string]interface{}{"capability": "read", "path": path, "rule_type": "event-forwarder-rule"}
		accessRules = append(accessRules, eventForwardersAccessMap)
	}

	return accessRules
}

func updateRoleAccessRules(ctx context.Context, name, description, deleteProtection string,
	accessRules []interface{}, m interface{}) (error, bool) {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var auditAccess, analyticsAccess, gwAnalyticsAccess, sraReportsAccess, usageReportsAccess, eventCenterAccess, eventForwardersAccess = "none", "none", "none", "none", "none", "none", "none"
	for _, rule := range accessRules {
		ruleType := rule.(map[string]interface{})["rule_type"].(string)
		rulePath := convertPathNameWithNoneOption(rule.(map[string]interface{})["path"].(string))

		switch ruleType {
		case "search-rule":
			auditAccess = rulePath
		case "reports-rule":
			analyticsAccess = rulePath
		case "gw-reports-rule":
			gwAnalyticsAccess = rulePath
		case "sra-reports-rule":
			sraReportsAccess = rulePath
		case "usage-reports-rule":
			usageReportsAccess = rulePath
		case "event-rule":
			eventCenterAccess = rulePath
		case "event-forwarder-rule":
			eventForwardersAccess = rulePath
		}
	}

	updateBody := akeyless_api.UpdateRole{
		Name:                 name,
		Token:                &token,
		AuditAccess:          akeyless_api.PtrString(auditAccess),
		AnalyticsAccess:      akeyless_api.PtrString(analyticsAccess),
		GwAnalyticsAccess:    akeyless_api.PtrString(gwAnalyticsAccess),
		SraReportsAccess:     akeyless_api.PtrString(sraReportsAccess),
		UsageReportsAccess:   akeyless_api.PtrString(usageReportsAccess),
		EventCenterAccess:    akeyless_api.PtrString(eventCenterAccess),
		EventForwarderAccess: akeyless_api.PtrString(eventForwardersAccess),
	}
	common.GetAkeylessPtr(&updateBody.Description, description)
	common.GetAkeylessPtr(&updateBody.DeleteProtection, deleteProtection)

	var apiErr akeyless_api.GenericOpenAPIError
	_, _, err := client.UpdateRole(ctx).Body(updateBody).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("%v", string(apiErr.Body())), false
		}
		return fmt.Errorf("%v", err), false
	}

	return nil, true
}

func extractAssocValues(assocs []akeyless_api.RoleAuthMethodAssociation) []interface{} {
	var assocValues []interface{}

	for _, assoc := range assocs {
		assocMap := make(map[string]interface{})
		assocMap["assoc_id"] = *assoc.AssocId
		assocMap["am_name"] = *assoc.AuthMethodName
		assocMap["access_id"] = *assoc.AuthMethodAccessId
		assocMap["case_sensitive"] = strconv.FormatBool(*assoc.SubClaimsCaseSensitive)

		sc := *assoc.AuthMethodSubClaims
		subClaims := make(map[string]interface{})
		for key, value := range sc {
			subClaims[key] = strings.Join(value, ",")
		}
		assocMap["sub_claims"] = subClaims

		assocValues = append(assocValues, assocMap)
	}

	return assocValues
}

// assocs are of type set, therefore it includes removed assocs
// that should not be part of the plan and we must cleanup them.
func cleanEmptyAssocs(d *schema.ResourceData) error {
	assocsSet := d.Get("assoc_auth_method").(*schema.Set)
	assocs := assocsSet.List()

	var assocsTotal []interface{}

	for _, assocInterface := range assocs {
		assoc := assocInterface.(map[string]interface{})
		if assoc["am_name"] != "" {
			assocsTotal = append(assocsTotal, assoc)
		}
	}

	err := d.Set("assoc_auth_method", assocsTotal)
	if err != nil {
		return err
	}
	return nil
}

func extractRoleRuleOldValues(roleRules []akeyless_api.PathRule) []interface{} {
	var roleRulesOldValues []interface{}

	for _, val := range roleRules {
		rulesMap := make(map[string]interface{})

		rulesMap["capability"] = val.Capabilities
		rulesMap["path"] = *val.Path
		rulesMap["rule_type"] = *val.Type

		roleRulesOldValues = append(roleRulesOldValues, rulesMap)
	}

	return roleRulesOldValues
}

func saveRoleAccessRuleOldValues(roleRules []akeyless_api.PathRule) []interface{} {

	var roleRulesOldValues = generateEmptyAccessRulesSet()

	for _, rule := range roleRules {
		rType := *rule.Type
		if isAccessRule(rType) {
			for i, val := range roleRulesOldValues {
				if val.(map[string]interface{})["rule_type"] == rType {
					roleRulesOldValues[i].(map[string]interface{})["capability"] = rule.Capabilities
					roleRulesOldValues[i].(map[string]interface{})["path"] = *rule.Path
				}
			}
		}
	}

	return roleRulesOldValues
}

func generateEmptyAccessRulesSet() []interface{} {
	accessCap := []string{"read"}
	accessCapAll := []string{"read", "list", "create", "update", "delete"}

	searchRule := map[string]interface{}{"capability": accessCap, "path": "", "rule_type": "search-rule"}
	reportsRule := map[string]interface{}{"capability": accessCap, "path": "", "rule_type": "reports-rule"}
	gwReportsRule := map[string]interface{}{"capability": accessCap, "path": "", "rule_type": "gw-reports-rule"}
	sraReportsRule := map[string]interface{}{"capability": accessCap, "path": "", "rule_type": "sra-reports-rule"}
	UsageReportRule := map[string]interface{}{"capability": accessCap, "path": "", "rule_type": "usage-reports-rule"}
	eventRule := map[string]interface{}{"capability": accessCap, "path": "", "rule_type": "event-rule"}
	eventForwarderRule := map[string]interface{}{"capability": accessCapAll, "path": "", "rule_type": "event-forwarder-rule"}

	return []interface{}{searchRule, reportsRule, gwReportsRule, sraReportsRule, UsageReportRule, eventRule, eventForwarderRule}
}

func isAccessRule(ruleType string) bool {
	return ruleType == "search-rule" || ruleType == "reports-rule" || ruleType == "gw-reports-rule" || ruleType == "sra-reports-rule" || ruleType == "usage-reports-rule" || ruleType == "event-rule" || ruleType == "event-forwarder-rule"
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
	case "usage-reports-rule":
		return d.Set("usage_reports_access", rolePath)
	case "event-rule":
		return d.Set("event_center_access", rolePath)
	case "event-forwarder-rule":
		return d.Set("event_forwarders_access", rolePath)
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

func convertPathNameWithNoneOption(rolePath string) string {
	switch rolePath {
	case "/*":
		return "all"
	case "/self":
		return "own"
	default:
		return "none"
	}
}

func convertPathNameOpposite(rolePath string) string {
	switch rolePath {
	case "all":
		return "/*"
	case "own":
		return "/self"
	default:
		return ""
	}
}

func getCapability(capability interface{}) []string {
	if capSlice, ok := capability.([]string); ok {
		return capSlice
	} else if capSet, ok := capability.(*schema.Set); ok {
		return common.ExpandStringList(capSet.List())
	}
	return nil
}

func isRulesEqual(rule1, rule2 map[string]interface{}) bool {
	rule1Cap := strings.Join(getCapability(rule1["capability"]), ",")
	rule1Path := rule1["path"].(string)
	rule1Type := rule1["rule_type"].(string)

	rule2Cap := strings.Join(getCapability(rule2["capability"]), ",")
	rule2Path := rule2["path"].(string)
	rule2Type := rule2["rule_type"].(string)

	return rule1Cap == rule2Cap && rule1Path == rule2Path && rule1Type == rule2Type
}

func isValidRuleType(ruleType string) bool {
	validRuleTypes := map[string]struct{}{
		"item-rule": {}, "role-rule": {}, "target-rule": {}, "auth-method-rule": {}, "sra-rule": {},
	}
	if _, valid := validRuleTypes[ruleType]; valid {
		return true
	}
	return false
}
