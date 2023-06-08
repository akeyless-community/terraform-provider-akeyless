// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGlobalsignTarget() *schema.Resource {
	return &schema.Resource{
		Description: "GlobalSign Target resource",
		Create:      resourceGlobalsignTargetCreate,
		Read:        resourceGlobalsignTargetRead,
		Update:      resourceGlobalsignTargetUpdate,
		Delete:      resourceGlobalsignTargetDelete,
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
				Description: "Timeout waiting for certificate validation",
				Default:     "5m",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
		},
	}
}

func resourceGlobalsignTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
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

	body := akeyless.CreateGlobalSignTarget{
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

	_, _, err := client.CreateGlobalSignTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("failed to create target: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to create target: %w", err)
	}

	d.SetId(name)

	return nil
}

func resourceGlobalsignTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GetTargetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GetTargetDetails(ctx).Body(body).Execute()
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

	if rOut.Target != nil {
		target := *rOut.Target

		if target.TargetName != nil {
			err := d.Set("name", *target.TargetName)
			if err != nil {
				return err
			}
		}
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

	if rOut.Value != nil {
		targetDetails := *rOut.Value

		if targetDetails.Username != nil {
			err := d.Set("username", *targetDetails.Username)
			if err != nil {
				return err
			}
		}
		if targetDetails.Password != nil {
			err := d.Set("password", *targetDetails.Password)
			if err != nil {
				return err
			}
		}
		if targetDetails.ProfileId != nil {
			err := d.Set("profile_id", *targetDetails.ProfileId)
			if err != nil {
				return err
			}
		}
		if targetDetails.FirstName != nil {
			err := d.Set("contact_first_name", *targetDetails.FirstName)
			if err != nil {
				return err
			}
		}
		if targetDetails.LastName != nil {
			err := d.Set("contact_last_name", *targetDetails.LastName)
			if err != nil {
				return err
			}
		}
		if targetDetails.Phone != nil {
			err := d.Set("contact_phone", *targetDetails.Phone)
			if err != nil {
				return err
			}
		}
		if targetDetails.Email != nil {
			err := d.Set("contact_email", *targetDetails.Email)
			if err != nil {
				return err
			}
		}
		if targetDetails.Timeout != nil {
			err := d.Set("timeout", *targetDetails.Timeout)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceGlobalsignTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
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

	body := akeyless.UpdateGlobalSignTarget{
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

	_, _, err := client.UpdateGlobalSignTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("failed to update target: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to update target: %w", err)
	}

	d.SetId(name)

	return nil
}

func resourceGlobalsignTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteTarget{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteTarget(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceGlobalsignTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GetTarget{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GetTarget(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}