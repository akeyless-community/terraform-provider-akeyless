package akeyless

import (
	"context"
	"encoding/json"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGroup() *schema.Resource {
	return &schema.Resource{
		Description: "Group resource",
		Create:      resourceGroupCreate,
		Read:        resourceGroupRead,
		Update:      resourceGroupUpdate,
		Delete:      resourceGroupDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGroupImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Group name",
				ForceNew:    true,
			},
			"group_alias": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A short group alias",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"user_assignment": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A json array string defining the access permission assignment for this group. Format: [{\"access_id\":\"p-abc123\",\"sub_claims\":{\"email\":[\"user@example.com\"]}}]. The access_id is the auth method access ID, and sub_claims is a map of claim names to arrays of allowed values.",
				StateFunc: func(v interface{}) string {
					// Normalize JSON by parsing and re-marshaling
					jsonStr := v.(string)
					var data interface{}
					if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
						return jsonStr
					}
					normalized, err := json.Marshal(data)
					if err != nil {
						return jsonStr
					}
					return string(normalized)
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					// Normalize and compare JSON
					var oldJSON, newJSON interface{}
					if err := json.Unmarshal([]byte(old), &oldJSON); err != nil {
						return false
					}
					if err := json.Unmarshal([]byte(new), &newJSON); err != nil {
						return false
					}
					// Marshal back to get normalized JSON
					oldNormalized, _ := json.Marshal(oldJSON)
					newNormalized, _ := json.Marshal(newJSON)
					return string(oldNormalized) == string(newNormalized)
				},
			},
		},
	}
}

func resourceGroupCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	groupAlias := d.Get("group_alias").(string)
	description := d.Get("description").(string)
	userAssignment := d.Get("user_assignment").(string)

	body := akeyless_api.CreateGroup{
		Name:       name,
		GroupAlias: groupAlias,
		Token:      &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.UserAssignment, userAssignment)

	_, resp, err := client.CreateGroup(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create group", resp, err)
	}

	d.SetId(name)

	return resourceGroupRead(d, m)
}

func resourceGroupRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.GetGroup{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GetGroup(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "failed to get group", res, err)
	}

	if rOut.GroupAlias != nil {
		err = d.Set("group_alias", *rOut.GroupAlias)
		if err != nil {
			return err
		}
	}

	if rOut.Description != nil {
		err = d.Set("description", *rOut.Description)
		if err != nil {
			return err
		}
	}

	// Marshal UserAssignments array to JSON string
	if len(rOut.UserAssignments) > 0 {
		// Normalize the user assignments to ensure sub_claims is always present
		var normalizedAssignments []map[string]interface{}
		for _, ua := range rOut.UserAssignments {
			assignment := make(map[string]interface{})
			if ua.AccessId != nil {
				assignment["access_id"] = *ua.AccessId
			}
			// Always include sub_claims, even if empty
			if ua.SubClaims != nil {
				assignment["sub_claims"] = ua.SubClaims
			} else {
				assignment["sub_claims"] = make(map[string]interface{})
			}
			normalizedAssignments = append(normalizedAssignments, assignment)
		}

		userAssignmentJSON, err := json.Marshal(normalizedAssignments)
		if err != nil {
			return fmt.Errorf("failed to marshal user_assignment: %w", err)
		}
		err = d.Set("user_assignment", string(userAssignmentJSON))
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceGroupUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	groupAlias := d.Get("group_alias").(string)
	description := d.Get("description").(string)
	userAssignment := d.Get("user_assignment").(string)

	body := akeyless_api.UpdateGroup{
		Name:       name,
		GroupAlias: groupAlias,
		Token:      &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.UserAssignment, userAssignment)

	_, resp, err := client.UpdateGroup(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update group", resp, err)
	}

	d.SetId(name)

	return resourceGroupRead(d, m)
}

func resourceGroupDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.DeleteGroup{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteGroup(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceGroupImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceGroupRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
