package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceArtifactoryTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Artifactory Target resource",
		Create:      resourceArtifactoryTargetCreate,
		Read:        resourceArtifactoryTargetRead,
		Update:      resourceArtifactoryTargetUpdate,
		Delete:      resourceArtifactoryTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceArtifactoryTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"base_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Base URL",
			},
			"artifactory_admin_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Artifactory Admin Name",
			},
			"artifactory_admin_pwd": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Artifactory Admin password",
			},
			"key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key used to encrypt the target secret value (if empty, the account default protectionKey key will be used)",
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

func resourceArtifactoryTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	baseUrl := d.Get("base_url").(string)
	artifactoryAdminName := d.Get("artifactory_admin_name").(string)
	artifactoryAdminPwd := d.Get("artifactory_admin_pwd").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.TargetCreateArtifactory{
		Name:                 name,
		BaseUrl:              baseUrl,
		ArtifactoryAdminName: artifactoryAdminName,
		ArtifactoryAdminPwd:  artifactoryAdminPwd,
		Token:                &token,
	}
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.TargetCreateArtifactory(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceArtifactoryTargetRead(d *schema.ResourceData, m interface{}) error {
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
		return common.HandleReadError(d, "can't get target details", res, err)
	}
	if rOut.Value.ArtifactoryTargetDetails.ArtifactoryBaseUrl != nil {
		err = d.Set("base_url", *rOut.Value.ArtifactoryTargetDetails.ArtifactoryBaseUrl)
		if err != nil {
			return err
		}
	}
	if rOut.Value.ArtifactoryTargetDetails.ArtifactoryAdminUsername != nil {
		err = d.Set("artifactory_admin_name", *rOut.Value.ArtifactoryTargetDetails.ArtifactoryAdminUsername)
		if err != nil {
			return err
		}
	}
	if rOut.Value.ArtifactoryTargetDetails.ArtifactoryAdminApikey != nil {
		err = d.Set("artifactory_admin_pwd", *rOut.Value.ArtifactoryTargetDetails.ArtifactoryAdminApikey)
		if err != nil {
			return err
		}
	}
	if rOut.Target.ProtectionKeyName != nil {
		err = d.Set("key", *rOut.Target.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.Target.Comment != nil {
		err := d.Set("description", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceArtifactoryTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	baseUrl := d.Get("base_url").(string)
	artifactoryAdminName := d.Get("artifactory_admin_name").(string)
	artifactoryAdminPwd := d.Get("artifactory_admin_pwd").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.TargetUpdateArtifactory{
		Name:                 name,
		BaseUrl:              baseUrl,
		ArtifactoryAdminName: artifactoryAdminName,
		ArtifactoryAdminPwd:  artifactoryAdminPwd,
		Token:                &token,
	}
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.TargetUpdateArtifactory(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceArtifactoryTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceArtifactoryTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceArtifactoryTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
