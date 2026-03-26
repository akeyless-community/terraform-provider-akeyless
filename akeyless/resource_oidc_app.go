package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func normalizePermissionAssignmentJSON(jsonStr string) string {
	var data []map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return jsonStr
	}
	for _, entry := range data {
		if sc, ok := entry["sub_claims"]; ok {
			if m, ok := sc.(map[string]interface{}); ok && len(m) == 0 {
				delete(entry, "sub_claims")
			}
		}
	}
	normalized, err := json.Marshal(data)
	if err != nil {
		return jsonStr
	}
	return string(normalized)
}

func resourceOidcApp() *schema.Resource {
	return &schema.Resource{
		Description: "OIDC App resource",
		Create:      resourceOidcAppCreate,
		Read:        resourceOidcAppRead,
		Update:      resourceOidcAppUpdate,
		Delete:      resourceOidcAppDelete,
		Importer: &schema.ResourceImporter{
			State: resourceOidcAppImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "OIDC App name",
				ForceNew:    true,
			},
			"accessibility": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "For personal password manager",
				Default:     "regular",
			},
			"audience": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma separated list of allowed audiences",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that used to encrypt the OIDC application (if empty, the account default protectionKey key will be used)",
			},
			"metadata": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Deprecated - use description",
			},
			"permission_assignment": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A json array string defining the access permission assignment for this OIDC app. Supports two formats: 1) Auth method: [{\"assignment_type\":\"AUTH_METHOD\",\"access_id\":\"p-abc123\",\"sub_claims\":{\"email\":[\"user@example.com\"]}}] 2) Group: [{\"assignment_type\":\"GROUP\",\"group_id\":\"grp-xyz789\"}]",
				StateFunc: func(v interface{}) string {
					jsonStr := v.(string)
					normalized := normalizePermissionAssignmentJSON(jsonStr)
					return normalized
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return normalizePermissionAssignmentJSON(old) == normalizePermissionAssignmentJSON(new)
				},
			},
			"public": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Set to true if the app is public (cannot keep secrets)",
			},
			"redirect_uris": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A comma separated list of allowed redirect uris",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"scopes": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A comma separated list of allowed scopes",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceOidcAppCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	accessibility := d.Get("accessibility").(string)
	audience := d.Get("audience").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	key := d.Get("key").(string)
	metadata := d.Get("metadata").(string)
	permissionAssignment := d.Get("permission_assignment").(string)
	public := d.Get("public").(bool)
	redirectUrisSet := d.Get("redirect_uris").(*schema.Set)
	redirectUris := common.ExpandStringList(redirectUrisSet.List())
	scopesSet := d.Get("scopes").(*schema.Set)
	scopes := common.ExpandStringList(scopesSet.List())
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless_api.CreateOidcApp{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Accessibility, accessibility)
	common.GetAkeylessPtr(&body.Audience, audience)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		customFieldsMap := make(map[string]string)
		for k, v := range itemCustomFields {
			customFieldsMap[k] = v.(string)
		}
		body.ItemCustomFields = &customFieldsMap
	}
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Metadata, metadata)
	common.GetAkeylessPtr(&body.PermissionAssignment, permissionAssignment)
	common.GetAkeylessPtr(&body.Public, public)
	common.GetAkeylessPtr(&body.RedirectUris, redirectUris)
	common.GetAkeylessPtr(&body.Scopes, scopes)
	if len(tags) > 0 {
		body.Tags = tags
	}

	_, resp, err := client.CreateOidcApp(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create OIDC App", resp, err)
	}

	d.SetId(name)

	return resourceOidcAppRead(d, m)
}

func resourceOidcAppRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DescribeItem{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DescribeItem(ctx).Body(body).Execute()
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

	if rOut.ItemMetadata != nil {
		err = d.Set("description", *rOut.ItemMetadata)
		if err != nil {
			return err
		}
	} else {
		err = d.Set("description", "")
		if err != nil {
			return err
		}
	}
	if rOut.ItemTags != nil {
		err = d.Set("tags", rOut.ItemTags)
		if err != nil {
			return err
		}
	}
	if rOut.ProtectionKeyName != nil {
		err = d.Set("key", *rOut.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}

	// Read OIDC-specific fields from item_general_info
	if rOut.ItemGeneralInfo != nil && rOut.ItemGeneralInfo.OidcClientInfo != nil {
		oidcInfo := rOut.ItemGeneralInfo.OidcClientInfo

		if oidcInfo.RedirectUris != nil && len(oidcInfo.RedirectUris) > 0 {
			// Filter out empty strings
			var validUris []string
			for _, uri := range oidcInfo.RedirectUris {
				if uri != "" {
					validUris = append(validUris, uri)
				}
			}
			if len(validUris) > 0 {
				err = d.Set("redirect_uris", validUris)
				if err != nil {
					return err
				}
			}
		}

		if oidcInfo.Scopes != nil && len(oidcInfo.Scopes) > 0 {
			// Filter out empty strings
			var validScopes []string
			for _, scope := range oidcInfo.Scopes {
				if scope != "" {
					validScopes = append(validScopes, scope)
				}
			}
			if len(validScopes) > 0 {
				err = d.Set("scopes", validScopes)
				if err != nil {
					return err
				}
			}
		}

		if oidcInfo.Audience != nil && len(oidcInfo.Audience) > 0 {
			// Join audience array into comma-separated string, filter empty
			var validAudience []string
			for _, aud := range oidcInfo.Audience {
				if aud != "" {
					validAudience = append(validAudience, aud)
				}
			}
			if len(validAudience) > 0 {
				audienceStr := strings.Join(validAudience, ",")
				err = d.Set("audience", audienceStr)
				if err != nil {
					return err
				}
			}
		}

		if oidcInfo.Public != nil {
			err = d.Set("public", *oidcInfo.Public)
			if err != nil {
				return err
			}
		}

		// Read permission_assignment from access_permission_assignment
		// Normalize to match input format (assignment_type, access_id, sub_claims)
		if oidcInfo.AccessPermissionAssignment != nil && len(oidcInfo.AccessPermissionAssignment) > 0 {
			var normalizedAssignments []map[string]interface{}
			for _, pa := range oidcInfo.AccessPermissionAssignment {
				assignment := make(map[string]interface{})
				if pa.AssignmentType != nil {
					assignment["assignment_type"] = *pa.AssignmentType
				}
				if pa.AccessId != nil {
					assignment["access_id"] = *pa.AccessId
				}
				if pa.AssignmentType != nil && *pa.AssignmentType == "AUTH_METHOD" {
					if pa.SubClaims != nil && len(*pa.SubClaims) > 0 {
						subClaims := make(map[string]interface{})
						for k, v := range *pa.SubClaims {
							subClaims[k] = v
						}
						assignment["sub_claims"] = subClaims
					}
				} else if pa.AssignmentType != nil && *pa.AssignmentType == "GROUP" {
					// For GROUP assignments, include group_id if available
					if pa.GroupId != nil {
						assignment["group_id"] = *pa.GroupId
					}
				}
				normalizedAssignments = append(normalizedAssignments, assignment)
			}

			permissionAssignmentJSON, err := json.Marshal(normalizedAssignments)
			if err != nil {
				return fmt.Errorf("failed to marshal permission_assignment: %w", err)
			}
			err = d.Set("permission_assignment", string(permissionAssignmentJSON))
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceOidcAppUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	accessibility := d.Get("accessibility").(string)
	audience := d.Get("audience").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	key := d.Get("key").(string)
	permissionAssignment := d.Get("permission_assignment").(string)
	public := d.Get("public").(bool)
	redirectUrisSet := d.Get("redirect_uris").(*schema.Set)
	redirectUris := common.ExpandStringList(redirectUrisSet.List())
	scopesSet := d.Get("scopes").(*schema.Set)
	scopes := common.ExpandStringList(scopesSet.List())
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	// Update OIDC-specific properties FIRST (this clears common fields)
	body := akeyless_api.UpdateOidcApp{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Audience, audience)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.PermissionAssignment, permissionAssignment)
	common.GetAkeylessPtr(&body.Public, public)
	if len(redirectUris) > 0 {
		redirectUrisStr := strings.Join(redirectUris, ",")
		common.GetAkeylessPtr(&body.RedirectUris, redirectUrisStr)
	}
	if len(scopes) > 0 {
		scopesStr := strings.Join(scopes, ",")
		common.GetAkeylessPtr(&body.Scopes, scopesStr)
	}

	_, resp, err := client.UpdateOidcApp(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update ", resp, err)
	}

	// Update common item properties LAST (to restore/set common fields after UpdateOidcApp)
	itemBody := akeyless_api.UpdateItem{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&itemBody.Accessibility, accessibility)
	common.GetAkeylessPtr(&itemBody.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&itemBody.Description, description)
	if len(itemCustomFields) > 0 {
		customFieldsJSON, err := json.Marshal(itemCustomFields)
		if err == nil {
			customFieldsStr := string(customFieldsJSON)
			common.GetAkeylessPtr(&itemBody.ItemCustomFields, &customFieldsStr)
		}
	}
	add, remove, err := common.GetTagsForUpdate(d, name, token, tags, client)
	if err == nil {
		if len(add) > 0 {
			itemBody.AddTag = add
		}
		if len(remove) > 0 {
			itemBody.RmTag = remove
		}
	}

	_, resp, err = client.UpdateItem(ctx).Body(itemBody).Execute()
	if err != nil {
		return common.HandleError("can't update ", resp, err)
	}

	d.SetId(name)

	return resourceOidcAppRead(d, m)
}

func resourceOidcAppDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.DeleteItem{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteItem(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceOidcAppImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceOidcAppRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
