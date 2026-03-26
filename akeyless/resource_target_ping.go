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

func resourcePingTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Ping Federate Target resource",
		Create:      resourcePingTargetCreate,
		Read:        resourcePingTargetRead,
		Update:      resourcePingTargetUpdate,
		Delete:      resourcePingTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourcePingTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"ping_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Ping URL",
			},
			"privileged_user": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Ping Federate privileged user",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Ping Federate privileged user password",
			},
			"administrative_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Ping Federate administrative port",
				Default:     "9999",
			},
			"authorization_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Ping Federate authorization port",
				Default:     "9031",
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
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourcePingTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	pingUrl := d.Get("ping_url").(string)
	privilegedUser := d.Get("privileged_user").(string)
	password := d.Get("password").(string)
	administrativePort := d.Get("administrative_port").(string)
	authorizationPort := d.Get("authorization_port").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.CreatePingTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.PingUrl, pingUrl)
	common.GetAkeylessPtr(&body.PrivilegedUser, privilegedUser)
	common.GetAkeylessPtr(&body.Password, password)
	common.GetAkeylessPtr(&body.AdministrativePort, administrativePort)
	common.GetAkeylessPtr(&body.AuthorizationPort, authorizationPort)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.CreatePingTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourcePingTargetRead(d *schema.ResourceData, m interface{}) error {
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

		if targetDetails.PingTargetDetails != nil {
			if targetDetails.PingTargetDetails.PingUrl != nil {
				err := d.Set("ping_url", *targetDetails.PingTargetDetails.PingUrl)
				if err != nil {
					return err
				}
			}
			if targetDetails.PingTargetDetails.PrivilegedUser != nil {
				err := d.Set("privileged_user", *targetDetails.PingTargetDetails.PrivilegedUser)
				if err != nil {
					return err
				}
			}
			if targetDetails.PingTargetDetails.UserPassword != nil {
				err := d.Set("password", *targetDetails.PingTargetDetails.UserPassword)
				if err != nil {
					return err
				}
			}
			if targetDetails.PingTargetDetails.AdministrativePort != nil {
				err := d.Set("administrative_port", *targetDetails.PingTargetDetails.AdministrativePort)
				if err != nil {
					return err
				}
			}
			if targetDetails.PingTargetDetails.AuthorizationPort != nil {
				err := d.Set("authorization_port", *targetDetails.PingTargetDetails.AuthorizationPort)
				if err != nil {
					return err
				}
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

func resourcePingTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	pingUrl := d.Get("ping_url").(string)
	privilegedUser := d.Get("privileged_user").(string)
	password := d.Get("password").(string)
	administrativePort := d.Get("administrative_port").(string)
	authorizationPort := d.Get("authorization_port").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.UpdatePingTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.PingUrl, pingUrl)
	common.GetAkeylessPtr(&body.PrivilegedUser, privilegedUser)
	common.GetAkeylessPtr(&body.Password, password)
	common.GetAkeylessPtr(&body.AdministrativePort, administrativePort)
	common.GetAkeylessPtr(&body.AuthorizationPort, authorizationPort)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.UpdatePingTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourcePingTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourcePingTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourcePingTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
