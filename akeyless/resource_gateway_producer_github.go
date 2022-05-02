package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceProducerGithub() *schema.Resource {
	return &schema.Resource{
		Description: "Github producer resource.",
		Create:      resourceProducerGithubCreate,
		Read:        resourceProducerGithubRead,
		Update:      resourceProducerGithubUpdate,
		Delete:      resourceProducerGithubDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerGithubImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Producer name",
				ForceNew:    true,
			},
			"installation_id": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Github application installation id",
			},
			"installation_repository": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Optional, instead of installation id, set a GitHub repository '<owner>/<repo-name>'",
			},
			"target_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Name of existing target to use in producer creation",
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
			"token_permissions": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "Tokens' allowed permissions. By default use installation allowed permissions. Input format: key=value pairs or JSON strings, e.g - -p contents=read -p issues=write or -p '{content:read}'",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"token_repositories": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "Tokens' allowed repositories. By default use installation allowed repositories. To specify multiple repositories use argument multiple times: -r RepoName1 -r RepoName2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceProducerGithubCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	installationId := d.Get("installation_id").(int)
	installationRepository := d.Get("installation_repository").(string)
	targetName := d.Get("target_name").(string)
	githubAppId := d.Get("github_app_id").(int)
	githubAppPrivateKey := d.Get("github_app_private_key").(string)
	githubBaseUrl := d.Get("github_base_url").(string)
	tokenPermissionsSet := d.Get("token_permissions").(*schema.Set)
	tokenPermissions := common.ExpandStringList(tokenPermissionsSet.List())
	tokenRepositoriesSet := d.Get("token_repositories").(*schema.Set)
	tokenRepositories := common.ExpandStringList(tokenRepositoriesSet.List())

	body := akeyless.GatewayCreateProducerGithub{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.InstallationId, installationId)
	common.GetAkeylessPtr(&body.InstallationRepository, installationRepository)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.GithubAppId, githubAppId)
	common.GetAkeylessPtr(&body.GithubAppPrivateKey, githubAppPrivateKey)
	common.GetAkeylessPtr(&body.GithubBaseUrl, githubBaseUrl)
	common.GetAkeylessPtr(&body.TokenPermissions, tokenPermissions)
	common.GetAkeylessPtr(&body.TokenRepositories, tokenRepositories)

	_, _, err := client.GatewayCreateProducerGithub(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerGithubRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GatewayGetProducer{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GatewayGetProducer(ctx).Body(body).Execute()
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
	if rOut.GithubAppId != nil {
		err = d.Set("github_app_id", *rOut.GithubAppId)
		if err != nil {
			return err
		}
	}
	if rOut.GithubAppPrivateKey != nil {
		err = d.Set("github_app_private_key", *rOut.GithubAppPrivateKey)
		if err != nil {
			return err
		}
	}
	if rOut.GithubBaseUrl != nil {
		err = d.Set("github_base_url", *rOut.GithubBaseUrl)
		if err != nil {
			return err
		}
	}

	/*
	   // TODO fix this
	   	if rOut.Name != nil {
	   		err = d.Set("name", *rOut.Name)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.InstallationId != nil {
	   		err = d.Set("installation_id", *rOut.InstallationId)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.InstallationRepository != nil {
	   		err = d.Set("installation_repository", *rOut.InstallationRepository)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   		if rOut.ItemTargetsAssoc != nil {
	   		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
	   		err = d.Set("target_name", targetName)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.TokenPermissions != nil {
	   		err = d.Set("token_permissions", *rOut.TokenPermissions)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.TokenRepositories != nil {
	   		err = d.Set("token_repositories", *rOut.TokenRepositories)
	   		if err != nil {
	   			return err
	   		}
	   	}

	   	common.GetSraWithDescribeItem(d, path, token, client)
	   	common.GetSraFromItem(d, rOut)
	   	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	*/

	d.SetId(path)

	return nil
}

func resourceProducerGithubUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	installationId := d.Get("installation_id").(int)
	installationRepository := d.Get("installation_repository").(string)
	targetName := d.Get("target_name").(string)
	githubAppId := d.Get("github_app_id").(int)
	githubAppPrivateKey := d.Get("github_app_private_key").(string)
	githubBaseUrl := d.Get("github_base_url").(string)
	tokenPermissionsSet := d.Get("token_permissions").(*schema.Set)
	tokenPermissions := common.ExpandStringList(tokenPermissionsSet.List())
	tokenRepositoriesSet := d.Get("token_repositories").(*schema.Set)
	tokenRepositories := common.ExpandStringList(tokenRepositoriesSet.List())

	/*
	 */

	body := akeyless.GatewayUpdateProducerGithub{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.InstallationId, installationId)
	common.GetAkeylessPtr(&body.InstallationRepository, installationRepository)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.GithubAppId, githubAppId)
	common.GetAkeylessPtr(&body.GithubAppPrivateKey, githubAppPrivateKey)
	common.GetAkeylessPtr(&body.GithubBaseUrl, githubBaseUrl)
	common.GetAkeylessPtr(&body.TokenPermissions, tokenPermissions)
	common.GetAkeylessPtr(&body.TokenRepositories, tokenRepositories)

	_, _, err := client.GatewayUpdateProducerGithub(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerGithubDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.GatewayDeleteProducer{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.GatewayDeleteProducer(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceProducerGithubImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GatewayGetProducer{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GatewayGetProducer(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
