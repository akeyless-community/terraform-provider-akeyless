package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGetTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Get target data source",
		Read:        dataSourceGetTargetRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"show_versions": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Include all target versions in reply",
				Default:     "false",
			},
			"target_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"target_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"target_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"comment": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"with_customer_fragment": {
				Type:        schema.TypeBool,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"protection_key_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"target_versions": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"client_permissions": {
				Type:        schema.TypeSet,
				Computed:    true,
				Required:    false,
				Description: "",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"last_version": {
				Type:        schema.TypeInt,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"target_items_assoc": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
		},
	}
}

func dataSourceGetTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	showVersions := d.Get("show_versions").(bool)

	body := akeyless.GetTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ShowVersions, showVersions)

	rOut, res, err := client.GetTarget(ctx).Body(body).Execute()
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
	err = d.Set("target_name", *rOut.TargetName)
	if err != nil {
		return err
	}
	err = d.Set("target_type", *rOut.TargetType)
	if err != nil {
		return err
	}
	err = d.Set("target_id", *rOut.TargetId)
	if err != nil {
		return err
	}
	err = d.Set("comment", *rOut.Comment)
	if err != nil {
		return err
	}
	err = d.Set("with_customer_fragment", *rOut.WithCustomerFragment)
	if err != nil {
		return err
	}
	err = d.Set("protection_key_name", *rOut.ProtectionKeyName)
	if err != nil {
		return err
	}
	marshalTargetVersions, err := json.Marshal(rOut.TargetVersions)
	if err != nil {
		return err
	}
	err = d.Set("target_versions", string(marshalTargetVersions))
	if err != nil {
		return err
	}
	err = d.Set("client_permissions", *rOut.ClientPermissions)
	if err != nil {
		return err
	}
	err = d.Set("last_version", *rOut.LastVersion)
	if err != nil {
		return err
	}
	marshalTargetItemsAssoc, err := json.Marshal(rOut.TargetItemsAssoc)
	if err != nil {
		return err
	}
	err = d.Set("target_items_assoc", string(marshalTargetItemsAssoc))
	if err != nil {
		return err
	}

	d.SetId(name)
	return nil
}
