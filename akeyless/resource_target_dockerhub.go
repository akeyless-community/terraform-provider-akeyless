package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceDockerhubTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Docker Hub Target resource",
		Create:      resourceDockerhubTargetCreate,
		Read:        resourceDockerhubTargetRead,
		Update:      resourceDockerhubTargetUpdate,
		Delete:      resourceDockerhubTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDockerhubTargetImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("dockerhub_password"), cty.GetAttrPath("dockerhub_password_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"dockerhub_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Username for docker repository",
			},
			"dockerhub_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Password for docker repository",
			},
			"dockerhub_password_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "Password for docker repository (write-only, not stored in state). Requires Terraform 1.11+. Bump dockerhub_password_wo_version to change it.",
			},
			"dockerhub_password_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for dockerhub_password_wo. Increment to update the value.",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
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

func resourceDockerhubTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	dockerhubUsername := d.Get("dockerhub_username").(string)
	dockerhubPassword, err := common.EffectiveSecretValue(d, "dockerhub_password", "dockerhub_password_wo")
	if err != nil {
		return err
	}
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.CreateDockerhubTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DockerhubUsername, dockerhubUsername)
	common.GetAkeylessPtr(&body.DockerhubPassword, dockerhubPassword)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.CreateDockerhubTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDockerhubTargetRead(d *schema.ResourceData, m interface{}) error {
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

		if targetDetails.DockerhubTargetDetails != nil {
			if targetDetails.DockerhubTargetDetails.UserName != nil {
				err := d.Set("dockerhub_username", *targetDetails.DockerhubTargetDetails.UserName)
				if err != nil {
					return err
				}
			}
			if targetDetails.DockerhubTargetDetails.Password != nil {
				err := common.SetSecretFromRead(d, "dockerhub_password", "dockerhub_password_wo", "dockerhub_password_wo_version", *targetDetails.DockerhubTargetDetails.Password)
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

func resourceDockerhubTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	dockerhubUsername := d.Get("dockerhub_username").(string)
	dockerhubPassword, err := common.EffectiveSecretValue(d, "dockerhub_password", "dockerhub_password_wo")
	if err != nil {
		return err
	}
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.UpdateDockerhubTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DockerhubUsername, dockerhubUsername)
	common.GetAkeylessPtr(&body.DockerhubPassword, dockerhubPassword)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.UpdateDockerhubTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDockerhubTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceDockerhubTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDockerhubTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
