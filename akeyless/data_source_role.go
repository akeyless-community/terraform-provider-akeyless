package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceRole() *schema.Resource {
	return &schema.Resource{
		Description: "Role data source",
		Read:        dataSourceRoleRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Role name",
			},
			"assoc_auth_method_with_rules": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Association between auth method and role with rules (JSON format)",
			},
			"access_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Access date of the role",
			},
			"access_date_display": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Access date display format",
			},
			"client_permissions": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Client permissions associated with the role",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"comment": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Comment about the role",
			},
			"creation_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Creation date of the role",
			},
			"delete_protection": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Protection from accidental deletion",
			},
			"modification_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Last modification date of the role",
			},
			"role_auth_methods_assoc": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Role auth methods association (JSON format)",
			},
			"role_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Role ID",
			},
			"role_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Role name",
			},
			"rules": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Role rules (JSON format)",
			},
		},
	}
}

func dataSourceRoleRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Get("name").(string)

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	body := akeyless_api.GetRole{
		Name:  name,
		Token: &token,
	}

	role, _, err := client.GetRole(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't get Role value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get Role value: %v", err)
	}

	d.SetId(name)

	roleAsJson, err := json.Marshal(role)
	if err != nil {
		return err
	}

	err = d.Set("assoc_auth_method_with_rules", string(roleAsJson))
	if err != nil {
		return err
	}

	if role.AccessDate != nil {
		err = d.Set("access_date", role.AccessDate.Format("2006-01-02T15:04:05Z07:00"))
		if err != nil {
			return err
		}
	}

	if role.AccessDateDisplay != nil {
		err = d.Set("access_date_display", *role.AccessDateDisplay)
		if err != nil {
			return err
		}
	}

	if role.ClientPermissions != nil {
		err = d.Set("client_permissions", role.ClientPermissions)
		if err != nil {
			return err
		}
	}

	if role.Comment != nil {
		err = d.Set("comment", *role.Comment)
		if err != nil {
			return err
		}
	}

	if role.CreationDate != nil {
		err = d.Set("creation_date", role.CreationDate.Format("2006-01-02T15:04:05Z07:00"))
		if err != nil {
			return err
		}
	}

	if role.DeleteProtection != nil {
		err = d.Set("delete_protection", *role.DeleteProtection)
		if err != nil {
			return err
		}
	}

	if role.ModificationDate != nil {
		err = d.Set("modification_date", role.ModificationDate.Format("2006-01-02T15:04:05Z07:00"))
		if err != nil {
			return err
		}
	}

	if role.RoleAuthMethodsAssoc != nil {
		roleAuthMethodsAssocJson, err := json.Marshal(role.RoleAuthMethodsAssoc)
		if err != nil {
			return err
		}
		err = d.Set("role_auth_methods_assoc", string(roleAuthMethodsAssocJson))
		if err != nil {
			return err
		}
	}

	if role.RoleId != nil {
		err = d.Set("role_id", *role.RoleId)
		if err != nil {
			return err
		}
	}

	if role.RoleName != nil {
		err = d.Set("role_name", *role.RoleName)
		if err != nil {
			return err
		}
	}

	if role.Rules != nil {
		rulesJson, err := json.Marshal(role.Rules)
		if err != nil {
			return err
		}
		err = d.Set("rules", string(rulesJson))
		if err != nil {
			return err
		}
	}

	return nil
}
