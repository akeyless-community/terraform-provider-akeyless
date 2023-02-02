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

func resourceGithubTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Github Target resource",
		Create:      resourceGithubTargetCreate,
		Read:        resourceGithubTargetRead,
		Update:      resourceGithubTargetUpdate,
		Delete:      resourceGithubTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGithubTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"github_app_id": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Github application id",
			},
			"github_app_private_key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Github application private key (base64 encoded key)",
			},
			"github_base_url": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Github base url",
				Default:     "https://api.github.com/",
			},
			"comment": {
				Type:        schema.TypeString,
				Optional:    true,
				Deprecated:  "Deprecated: Use description instead",
				Description: "Comment about the target",
			},
			"description": {
				Type:        schema.TypeString,
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

func resourceGithubTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	githubAppId := d.Get("github_app_id").(int)
	githubAppPrivateKey := d.Get("github_app_private_key").(string)
	githubBaseUrl := d.Get("github_base_url").(string)
	comment := d.Get("comment").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)

	body := akeyless.CreateGithubTarget{
		Name:  name,
		Token: &token,
	}

	common.GetAkeylessPtr(&body.GithubAppId, githubAppId)
	common.GetAkeylessPtr(&body.GithubAppPrivateKey, githubAppPrivateKey)
	common.GetAkeylessPtr(&body.GithubBaseUrl, githubBaseUrl)
	common.GetAkeylessPtr(&body.Comment, comment)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)

	_, _, err := client.CreateGithubTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceGithubTargetRead(d *schema.ResourceData, m interface{}) error {
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
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}

	if rOut.Value.GithubAppId != nil {
		err = d.Set("github_app_id", *rOut.Value.GithubAppId)
		if err != nil {
			return err
		}
	}
	if rOut.Value.GithubAppPrivateKey != nil {
		err = d.Set("github_app_private_key", *rOut.Value.GithubAppPrivateKey)
		if err != nil {
			return err
		}
	}
	if rOut.Value.GithubBaseUrl != nil {
		err = d.Set("github_base_url", *rOut.Value.GithubBaseUrl)
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

func resourceGithubTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	githubAppId := d.Get("github_app_id").(int)
	githubAppPrivateKey := d.Get("github_app_private_key").(string)
	githubBaseUrl := d.Get("github_base_url").(string)
	comment := d.Get("comment").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)

	body := akeyless.UpdateGithubTarget{
		Name:  name,
		Token: &token,
	}

	common.GetAkeylessPtr(&body.GithubAppId, githubAppId)
	common.GetAkeylessPtr(&body.GithubAppPrivateKey, githubAppPrivateKey)
	common.GetAkeylessPtr(&body.GithubBaseUrl, githubBaseUrl)
	common.GetAkeylessPtr(&body.Comment, comment)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)

	_, _, err := client.UpdateGithubTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceGithubTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceGithubTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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
