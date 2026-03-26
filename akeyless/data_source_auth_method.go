package akeyless

import (
	"context"
	"errors"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceAuthMethod() *schema.Resource {
	return &schema.Resource{
		Description: "Auth Method data source",
		Read:        dataSourceAuthMethodRead,
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path where the auth method is stored.",
			},
			"account_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The account ID associated with the auth method.",
			},
			"access_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The access ID of the auth method.",
			},
			"access_date_display": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The display format of the access date.",
			},
			"associated_gw_ids": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The list of gateway IDs associated with the auth method.",
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
			},
			"auth_method_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The unique identifier of the auth method.",
			},
			"auth_method_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The name of the auth method.",
			},
			"client_permissions": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "The list of client permissions.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"delete_protection": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether delete protection is enabled.",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The description of the auth method.",
			},
			"is_approved": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the auth method is approved.",
			},
			"access_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The access date of the auth method.",
			},
			"creation_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The creation date of the auth method.",
			},
			"modification_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The modification date of the auth method.",
			},
		},
	}
}

func dataSourceAuthMethodRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	gsvBody := akeyless_api.AuthMethodGet{
		Name:  path,
		Token: &token,
	}

	gsvOut, _, err := client.AuthMethodGet(ctx).Body(gsvBody).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't get Auth Method: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get Auth Method: %v", err)
	}

	if err := d.Set("account_id", gsvOut.AccountId); err != nil {
		return err
	}
	if err := d.Set("access_id", gsvOut.AuthMethodAccessId); err != nil {
		return err
	}
	if err := d.Set("access_date_display", gsvOut.AccessDateDisplay); err != nil {
		return err
	}
	if err := d.Set("associated_gw_ids", gsvOut.AssociatedGwIds); err != nil {
		return err
	}
	if err := d.Set("auth_method_id", gsvOut.AuthMethodId); err != nil {
		return err
	}
	if err := d.Set("auth_method_name", gsvOut.AuthMethodName); err != nil {
		return err
	}
	if err := d.Set("client_permissions", gsvOut.ClientPermissions); err != nil {
		return err
	}
	if err := d.Set("delete_protection", gsvOut.DeleteProtection); err != nil {
		return err
	}
	if err := d.Set("description", gsvOut.Description); err != nil {
		return err
	}
	if err := d.Set("is_approved", gsvOut.IsApproved); err != nil {
		return err
	}
	if gsvOut.AccessDate != nil {
		if err := d.Set("access_date", gsvOut.AccessDate.String()); err != nil {
			return err
		}
	}
	if gsvOut.CreationDate != nil {
		if err := d.Set("creation_date", gsvOut.CreationDate.String()); err != nil {
			return err
		}
	}
	if gsvOut.ModificationDate != nil {
		if err := d.Set("modification_date", gsvOut.ModificationDate.String()); err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}
