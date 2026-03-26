package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
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
				Default:     false,
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
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
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
			"access_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Access date of the target",
			},
			"access_date_display": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Access date display of the target",
			},
			"access_request_status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Access request status of the target",
			},
			"attributes": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Target attributes",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"creation_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Creation date of the target",
			},
			"is_access_request_enabled": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether access request is enabled for the target",
			},
			"modification_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Modification date of the target",
			},
			"parent_target_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Parent target name",
			},
			"target_details": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Target details",
			},
			"target_sub_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Target sub type",
			},
		},
	}
}

func dataSourceGetTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	showVersions := d.Get("show_versions").(bool)

	body := akeyless_api.TargetGet{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ShowVersions, showVersions)

	rOut, res, err := client.TargetGet(ctx).Body(body).Execute()
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
	if rOut.TargetName != nil {
		err := d.Set("target_name", *rOut.TargetName)
		if err != nil {
			return err
		}
	}
	if rOut.TargetType != nil {
		err := d.Set("target_type", *rOut.TargetType)
		if err != nil {
			return err
		}
	}
	if rOut.TargetId != nil {
		err := d.Set("target_id", *rOut.TargetId)
		if err != nil {
			return err
		}
	}
	if rOut.Comment != nil {
		err := d.Set("description", *rOut.Comment)
		if err != nil {
			return err
		}
	}
	if rOut.WithCustomerFragment != nil {
		err := d.Set("with_customer_fragment", *rOut.WithCustomerFragment)
		if err != nil {
			return err
		}
	}
	if rOut.ProtectionKeyName != nil {
		err := d.Set("protection_key_name", *rOut.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.TargetVersions != nil {
		marshalTargetVersions, err := json.Marshal(rOut.TargetVersions)
		if err != nil {
			return err
		}
		err = d.Set("target_versions", string(marshalTargetVersions))
		if err != nil {
			return err
		}
	}
	if rOut.ClientPermissions != nil {
		err := d.Set("client_permissions", rOut.ClientPermissions)
		if err != nil {
			return err
		}
	}
	if rOut.LastVersion != nil {
		err := d.Set("last_version", *rOut.LastVersion)
		if err != nil {
			return err
		}
	}
	if rOut.TargetItemsAssoc != nil {
		marshalTargetItemsAssoc, err := json.Marshal(rOut.TargetItemsAssoc)
		if err != nil {
			return err
		}
		err = d.Set("target_items_assoc", string(marshalTargetItemsAssoc))
		if err != nil {
			return err
		}
	}
	if rOut.AccessDate != nil {
		err := d.Set("access_date", rOut.AccessDate.String())
		if err != nil {
			return err
		}
	}
	if rOut.AccessDateDisplay != nil {
		err := d.Set("access_date_display", *rOut.AccessDateDisplay)
		if err != nil {
			return err
		}
	}
	if rOut.AccessRequestStatus != nil {
		err := d.Set("access_request_status", *rOut.AccessRequestStatus)
		if err != nil {
			return err
		}
	}
	if rOut.Attributes != nil {
		// Convert map[string]interface{} to map[string]string for Terraform
		attrs := make(map[string]string)
		for k, v := range rOut.Attributes {
			if v != nil {
				attrs[k] = fmt.Sprintf("%v", v)
			}
		}
		err := d.Set("attributes", attrs)
		if err != nil {
			return err
		}
	}
	if rOut.CreationDate != nil {
		err := d.Set("creation_date", rOut.CreationDate.String())
		if err != nil {
			return err
		}
	}
	if rOut.IsAccessRequestEnabled != nil {
		err := d.Set("is_access_request_enabled", *rOut.IsAccessRequestEnabled)
		if err != nil {
			return err
		}
	}
	if rOut.ModificationDate != nil {
		err := d.Set("modification_date", rOut.ModificationDate.String())
		if err != nil {
			return err
		}
	}
	if rOut.ParentTargetName != nil {
		err := d.Set("parent_target_name", *rOut.ParentTargetName)
		if err != nil {
			return err
		}
	}
	if rOut.TargetDetails != nil {
		err := d.Set("target_details", *rOut.TargetDetails)
		if err != nil {
			return err
		}
	}
	if rOut.TargetSubType != nil {
		err := d.Set("target_sub_type", *rOut.TargetSubType)
		if err != nil {
			return err
		}
	}

	d.SetId(name)
	return nil
}
