package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGitlabTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Gitlab Target resource",
		Create:      resourceGitlabTargetCreate,
		Read:        resourceGitlabTargetRead,
		Update:      resourceGitlabTargetUpdate,
		Delete:      resourceGitlabTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGitlabTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"gitlab_access_token": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Gitlab access token",
			},
			"gitlab_certificate": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Gitlab tls certificate (base64 encoded)",
			},
			"gitlab_url": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Gitlab base url",
				Default:     "https://gitlab.com/",
			},
			"description": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Description of the object",
			},
			"key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used.",
			},
		},
	}
}

func resourceGitlabTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	gitlabAccessToken := d.Get("gitlab_access_token").(string)
	gitlabCertificate := d.Get("gitlab_certificate").(string)
	gitlabUrl := d.Get("gitlab_url").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)

	body := akeyless_api.CreateGitlabTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GitlabAccessToken, gitlabAccessToken)
	common.GetAkeylessPtr(&body.GitlabCertificate, gitlabCertificate)
	common.GetAkeylessPtr(&body.GitlabUrl, gitlabUrl)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)

	_, _, err := client.CreateGitlabTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceGitlabTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.GetTargetDetails{
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
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}

	if rOut.Value.GitlabTargetDetails.GitlabAccessToken != nil {
		err = d.Set("gitlab_access_token", *rOut.Value.GitlabTargetDetails.GitlabAccessToken)
		if err != nil {
			return err
		}
	}
	if rOut.Value.GitlabTargetDetails.GitlabCertificate != nil {
		err = d.Set("gitlab_certificate", *rOut.Value.GitlabTargetDetails.GitlabCertificate)
		if err != nil {
			return err
		}
	}
	if rOut.Value.GitlabTargetDetails.GitlabUrl != nil {
		err = d.Set("gitlab_url", *rOut.Value.GitlabTargetDetails.GitlabUrl)
		if err != nil {
			return err
		}
	}

	if rOut.Target.Comment != nil {
		err = d.Set("description", *rOut.Target.Comment)
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

	d.SetId(path)

	return nil
}

func resourceGitlabTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	gitlabAccessToken := d.Get("gitlab_access_token").(string)
	gitlabCertificate := d.Get("gitlab_certificate").(string)
	gitlabUrl := d.Get("gitlab_url").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)

	body := akeyless_api.UpdateGitlabTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GitlabAccessToken, gitlabAccessToken)
	common.GetAkeylessPtr(&body.GitlabCertificate, gitlabCertificate)
	common.GetAkeylessPtr(&body.GitlabUrl, gitlabUrl)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)

	_, _, err := client.UpdateGitlabTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceGitlabTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.DeleteTarget{
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

func resourceGitlabTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	path := d.Id()

	err := resourceGitlabTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
