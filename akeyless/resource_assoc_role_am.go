// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	ErrFormatMsg = "resource-id should be one of the following: <role_name>:<am_name> or <role_name>:<association_id>"
)

func resourceAssocRoleAm() *schema.Resource {
	return &schema.Resource{
		Description: "Association between role and auth method",
		Create:      resourceAssocRoleAmCreate,
		Read:        resourceAssocRoleAmRead,
		Update:      resourceAssocRoleAmUpdate,
		Delete:      resourceAssocRoleAmDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAssocRoleAmImport,
		},
		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The role to associate",
			},
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
				Required:    false,
				Optional:    true,
				Description: "Treat sub claims as case-sensitive",
				Default:     "true",
			},
		},
	}
}

func resourceAssocRoleAmCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	roleName := d.Get("role_name").(string)
	amName := d.Get("am_name").(string)
	caseSensitive := d.Get("case_sensitive").(string)

	subClaims := d.Get("sub_claims").(map[string]interface{})
	sc := make(map[string]string, len(subClaims))
	for k, v := range subClaims {
		sc[k] = v.(string)
	}

	body := akeyless.AssocRoleAuthMethod{
		RoleName: roleName,
		AmName:   amName,
		Token:    &token,
	}
	body.SubClaims = &sc
	common.GetAkeylessPtr(&body.CaseSensitive, caseSensitive)

	r, _, err := client.AssocRoleAuthMethod(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create association: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create association: %v", err)
	}
	if r.AssocId == nil {
		return fmt.Errorf("can't create association")
	}
	d.SetId(*r.AssocId)

	return nil
}

func resourceAssocRoleAmRead(d *schema.ResourceData, m interface{}) error {

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
	if role.RoleAuthMethodsAssoc != nil {
		for _, acc := range *role.RoleAuthMethodsAssoc {
			if acc.AssocId != nil && *acc.AssocId == id {
				if acc.AuthMethodName != nil {
					err = d.Set("am_name", *acc.AuthMethodName)
					if err != nil {
						return err
					}
				}
				if acc.AuthMethodSubClaims != nil {
					sc := make(map[string]string, len(*acc.AuthMethodSubClaims))
					for k, v := range *acc.AuthMethodSubClaims {
						sc[k] = strings.Join(v, ",")
					}
					err = d.Set("sub_claims", sc)
					if err != nil {
						return err
					}
				}
				if acc.SubClaimsCaseSensitive != nil {
					cs := "true"
					if !*acc.SubClaimsCaseSensitive {
						cs = "false"
					}
					err = d.Set("case_sensitive", cs)
					if err != nil {
						return err
					}
				}

				d.SetId(id)
				return nil
			}
		}
	}

	// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
	d.SetId("")
	return nil
}

func resourceAssocRoleAmUpdate(d *schema.ResourceData, m interface{}) error {

	err := validateAssocRoleAmUpdateParams(d)
	if err != nil {
		return fmt.Errorf("can't update association: %v", err)
	}

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	subClaims := d.Get("sub_claims").(map[string]interface{})
	sc := make(map[string]string, len(subClaims))
	for k, v := range subClaims {
		sc[k] = v.(string)
	}
	caseSensitive := d.Get("case_sensitive").(string)

	id := d.Id()

	body := akeyless.UpdateAssoc{
		AssocId: id,
		Token:   &token,
	}
	body.SubClaims = &sc
	common.GetAkeylessPtr(&body.CaseSensitive, caseSensitive)

	_, _, err = client.UpdateAssoc(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update association: %s", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update association: %w", err)
	}

	d.SetId(id)

	return nil
}

func resourceAssocRoleAmDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	id := d.Id()

	deleteItem := akeyless.DeleteRoleAssociation{
		Token:   &token,
		AssocId: id,
	}

	ctx := context.Background()
	_, _, err := client.DeleteRoleAssociation(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

type AssocParams struct {
	RoleName string
	AmName   string
	AssocId  string
}

func resourceAssocRoleAmImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	assocParams, err := getAssocImportParams(d)
	if err != nil {
		return nil, err
	}

	roleName := assocParams.RoleName
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

	if role.RoleAuthMethodsAssoc != nil {
		if assocParams.AmName != "" {
			return importByAuthMethod(d, role, assocParams.AmName)
		}
		return importByAssocId(d, role, assocParams.AssocId)
	}

	id := d.Id()
	d.SetId("")
	return nil, fmt.Errorf("association %v was not found", id)

}

func importByAuthMethod(d *schema.ResourceData, role akeyless.Role, amName string) ([]*schema.ResourceData, error) {
	id := d.Id()

	assocs := *role.RoleAuthMethodsAssoc
	count := countRoleAmAssocs(assocs, amName)
	if count == 0 {
		return nil, fmt.Errorf("association %v was not found", id)
	}
	if count > 1 {
		return nil, fmt.Errorf("found more than one result for %s. please import by association id: <role_name>:<association_id>", id)
	}

	for _, acc := range assocs {
		if acc.AuthMethodName != nil && *acc.AuthMethodName == amName {
			err := fillAssocFields(d, acc)
			if err != nil {
				return nil, err
			}

			if acc.AssocId != nil {
				d.SetId(*acc.AssocId)
			}
			return []*schema.ResourceData{d}, nil
		}
	}

	d.SetId("")
	return nil, fmt.Errorf("association %v was not found", id)
}

func importByAssocId(d *schema.ResourceData, role akeyless.Role, assocId string) ([]*schema.ResourceData, error) {
	id := d.Id()

	for _, acc := range *role.RoleAuthMethodsAssoc {
		if acc.AssocId != nil && *acc.AssocId == assocId {
			err := fillAssocFields(d, acc)
			if err != nil {
				return nil, err
			}

			d.SetId(assocId)
			return []*schema.ResourceData{d}, nil
		}
	}

	d.SetId("")
	return nil, fmt.Errorf("association %v was not found", id)
}

func fillAssocFields(d *schema.ResourceData, acc akeyless.RoleAuthMethodAssociation) error {
	if acc.AuthMethodName != nil {
		err := d.Set("am_name", *acc.AuthMethodName)
		if err != nil {
			return err
		}
	}
	if acc.AuthMethodSubClaims != nil {
		sc := make(map[string]string, len(*acc.AuthMethodSubClaims))
		for k, v := range *acc.AuthMethodSubClaims {
			sc[k] = strings.Join(v, ",")
		}
		err := d.Set("sub_claims", sc)
		if err != nil {
			return err
		}
	}
	if acc.SubClaimsCaseSensitive != nil {
		cs := "true"
		if !*acc.SubClaimsCaseSensitive {
			cs = "false"
		}
		err := d.Set("case_sensitive", cs)
		if err != nil {
			return err
		}
	}
	return nil
}

func countRoleAmAssocs(assocs []akeyless.RoleAuthMethodAssociation, amName string) int {
	count := 0
	for _, acc := range assocs {
		if acc.AuthMethodName != nil && *acc.AuthMethodName == amName {
			count++
		}
	}
	return count
}

func getAssocImportParams(d *schema.ResourceData) (*AssocParams, error) {

	attr := strings.Split(d.Id(), ":")
	if len(attr) != 2 {
		return nil, fmt.Errorf(ErrFormatMsg)
	}

	assocParams := AssocParams{
		RoleName: attr[0],
		AmName:   "",
		AssocId:  "",
	}

	if isAssocId(attr[1]) {
		assocParams.AssocId = attr[1]
	} else {
		assocParams.AmName = attr[1]
	}

	return &assocParams, nil
}

func isAssocId(s string) bool {
	// e.g. ass-abcdef123456fedcba
	return strings.HasPrefix(s, "ass-") && len(s) == 24
}

// every resource_associate_role_auth_method can relate to exactly 1 assoc.
// updating its role_name or am_name meaning destroy and re-create the resource.
// therefore only sub_claims and case_sensitive are able to update.
// if you wish to update role_name or am_name, destroy the resource first.
func validateAssocRoleAmUpdateParams(d *schema.ResourceData) error {
	paramsMustNotUpdate := []string{"role_name", "am_name"}
	return common.GetErrorOnUpdateParam(d, paramsMustNotUpdate)
}
