package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
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
				Description: "Artifactory REST URL, must end with artifactory postfix",
			},
			"artifactory_admin_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Admin name",
			},
			"artifactory_admin_pwd": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Admin API Key/Password",
			},
			"key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The name of a key that used to encrypt the target secret value (if empty, the account default protectionKey key will be used)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
		},
	}
}

func resourceArtifactoryTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	baseUrl := d.Get("base_url").(string)
	artifactoryAdminName := d.Get("artifactory_admin_name").(string)
	artifactoryAdminPwd := d.Get("artifactory_admin_pwd").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetCreateArtifactory{
		Name:                 name,
		BaseUrl:              baseUrl,
		ArtifactoryAdminName: artifactoryAdminName,
		ArtifactoryAdminPwd:  artifactoryAdminPwd,
		Token:                &token,
	}
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.TargetCreateArtifactory(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Target: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Target: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceArtifactoryTargetRead(d *schema.ResourceData, m interface{}) error {
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
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
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

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	baseUrl := d.Get("base_url").(string)
	artifactoryAdminName := d.Get("artifactory_admin_name").(string)
	artifactoryAdminPwd := d.Get("artifactory_admin_pwd").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetUpdateArtifactory{
		Name:                 name,
		BaseUrl:              baseUrl,
		ArtifactoryAdminName: artifactoryAdminName,
		ArtifactoryAdminPwd:  artifactoryAdminPwd,
		Token:                &token,
	}
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.TargetUpdateArtifactory(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
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
