package akeyless

import (
	"context"
	"strconv"

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
			"lock_on_read":     {Type: schema.TypeString, Optional: true, Description: "Lock after read"},
			"lock_ttl":         {Type: schema.TypeString, Optional: true, Description: "Lock TTL in minutes"},
			"rotate_on_unlock": {Type: schema.TypeString, Optional: true, Description: "Rotate after unlock"},

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
				Computed:    true,
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

	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))

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

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "failed to get target details", res, err)
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

	itemOut, _, err := client.DescribeItem(ctx).Body(akeyless_api.DescribeItem{Name: path, Token: &token}).Execute()
	if err != nil {
		return err
	}
	if itemOut.ItemGeneralInfo != nil {
		info := itemOut.ItemGeneralInfo
		if info.LockOnRead != nil {
			if err := d.Set("lock_on_read", strconv.FormatBool(*info.LockOnRead)); err != nil {
				return err
			}
		}
		if info.LockTtl != nil {
			if err := d.Set("lock_ttl", strconv.FormatInt(*info.LockTtl, 10)); err != nil {
				return err
			}
		}
		if info.RotateOnUnlock != nil {
			if err := d.Set("rotate_on_unlock", strconv.FormatBool(*info.RotateOnUnlock)); err != nil {
				return err
			}
		} else if info.PendingRotateOnUnlock != nil {
			if err := d.Set("rotate_on_unlock", strconv.FormatBool(*info.PendingRotateOnUnlock)); err != nil {
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

	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))

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
