// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGlobalsignTarget() *schema.Resource {
	return &schema.Resource{
		Description:        "GlobalSign Target resource",
		DeprecationMessage: "use akeyless_target_globalsign resource instead",
		Create:             resourceGlobalsignTargetCreate,
		Read:               resourceGlobalsignTargetRead,
		Update:             resourceGlobalsignTargetUpdate,
		Delete:             resourceGlobalsignTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGlobalsignTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Username of the GlobalSign GCC account",
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Password of the GlobalSign GCC account",
			},
			"profile_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Profile ID of the GlobalSign GCC account",
			},
			"contact_first_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "First name of the GlobalSign GCC account contact",
			},
			"contact_last_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Last name of the GlobalSign GCC account contact",
			},
			"contact_phone": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Telephone of the GlobalSign GCC account contact",
			},
			"contact_email": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Email of the GlobalSign GCC account contact",
			},
			"timeout": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Timeout waiting for certificate validation in Duration format (1h - 1 Hour, 20m - 20 Minutes, 33m3s - 33 Minutes and 3 Seconds), maximum 1h.",
				Default:     "5m",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of a key that used to encrypt the target secret value (if empty, the account default protectionKey key will be used)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceGlobalsignTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	profileId := d.Get("profile_id").(string)
	contactFirstName := d.Get("contact_first_name").(string)
	contactLastName := d.Get("contact_last_name").(string)
	contactPhone := d.Get("contact_phone").(string)
	contactEmail := d.Get("contact_email").(string)
	timeout := d.Get("timeout").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.TargetCreateGlobalSign{
		Name:             name,
		Username:         username,
		Password:         password,
		ProfileId:        profileId,
		ContactFirstName: contactFirstName,
		ContactLastName:  contactLastName,
		ContactPhone:     contactPhone,
		ContactEmail:     contactEmail,
		Token:            &token,
	}
	common.GetAkeylessPtr(&body.Timeout, timeout)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.TargetCreateGlobalSign(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceGlobalsignTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("failed to get target details: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to get target details: %w", err)
	}

	if rOut.Value != nil {
		targetDetails := *rOut.Value

		if targetDetails.GlobalsignTargetDetails.Username != nil {
			err := d.Set("username", *targetDetails.GlobalsignTargetDetails.Username)
			if err != nil {
				return err
			}
		}
		if targetDetails.GlobalsignTargetDetails.Password != nil {
			err := d.Set("password", *targetDetails.GlobalsignTargetDetails.Password)
			if err != nil {
				return err
			}
		}
		if targetDetails.GlobalsignTargetDetails.ProfileId != nil {
			err := d.Set("profile_id", *targetDetails.GlobalsignTargetDetails.ProfileId)
			if err != nil {
				return err
			}
		}
		if targetDetails.GlobalsignTargetDetails.FirstName != nil {
			err := d.Set("contact_first_name", *targetDetails.GlobalsignTargetDetails.FirstName)
			if err != nil {
				return err
			}
		}
		if targetDetails.GlobalsignTargetDetails.LastName != nil {
			err := d.Set("contact_last_name", *targetDetails.GlobalsignTargetDetails.LastName)
			if err != nil {
				return err
			}
		}
		if targetDetails.GlobalsignTargetDetails.Phone != nil {
			err := d.Set("contact_phone", *targetDetails.GlobalsignTargetDetails.Phone)
			if err != nil {
				return err
			}
		}
		if targetDetails.GlobalsignTargetDetails.Email != nil {
			err := d.Set("contact_email", *targetDetails.GlobalsignTargetDetails.Email)
			if err != nil {
				return err
			}
		}
		if targetDetails.GlobalsignTargetDetails.Timeout != nil {
			timeout := *targetDetails.GlobalsignTargetDetails.Timeout
			duration := common.ConvertNanoSecondsIntoDurationString(timeout)

			err := d.Set("timeout", duration)
			if err != nil {
				return err
			}
		}
	}

	if rOut.Target != nil {
		target := *rOut.Target

		if target.Comment != nil {
			err := d.Set("description", *target.Comment)
			if err != nil {
				return err
			}
		}
		if target.ProtectionKeyName != nil {
			err = d.Set("key", *target.ProtectionKeyName)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceGlobalsignTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	profileId := d.Get("profile_id").(string)
	contactFirstName := d.Get("contact_first_name").(string)
	contactLastName := d.Get("contact_last_name").(string)
	contactPhone := d.Get("contact_phone").(string)
	contactEmail := d.Get("contact_email").(string)
	timeout := d.Get("timeout").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.TargetUpdateGlobalSign{
		Name:             name,
		Username:         username,
		Password:         password,
		ProfileId:        profileId,
		ContactFirstName: contactFirstName,
		ContactLastName:  contactLastName,
		ContactPhone:     contactPhone,
		ContactEmail:     contactEmail,
		Token:            &token,
	}
	common.GetAkeylessPtr(&body.Timeout, timeout)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.TargetUpdateGlobalSign(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceGlobalsignTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.TargetDelete{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.TargetDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceGlobalsignTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceGlobalsignTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
