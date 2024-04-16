package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceProducerGithub() *schema.Resource {
	return &schema.Resource{
		Description:        "Github producer resource.",
		DeprecationMessage: "Deprecated: Please use new resource: akeyless_dynamic_secret_github",
		Create:             resourceProducerGithubCreate,
		Read:               resourceProducerGithubRead,
		Update:             resourceProducerGithubUpdate,
		Delete:             resourceProducerGithubDelete,
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

	// installation_id is relevant when installation_repository isn't (need exactly one)
	if rOut.GithubInstallationId != nil {
		if d.Get("installation_repository").(string) == "" {
			err = d.Set("installation_id", *rOut.GithubInstallationId)
			if err != nil {
				return err
			}
		}
	}
	// installation_repository is relevant when installation_id isn't (need exactly one)
	if rOut.GithubRepositoryPath != nil {
		if d.Get("installation_id").(int) == 0 {
			err = d.Set("installation_repository", *rOut.GithubRepositoryPath)
			if err != nil {
				return err
			}
		}
	}

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
		if err != nil {
			return err
		}
	}
	if rOut.GithubInstallationTokenPermissions != nil {
		permissionsMap := *rOut.GithubInstallationTokenPermissions
		tokenPermissionsSet := d.Get("token_permissions").(*schema.Set)
		tokenPermissionsList := common.ExpandStringList(tokenPermissionsSet.List())
		relevantPermissionsList := removeIgnoredEntriesFromList(permissionsMap, tokenPermissionsList)

		err = d.Set("token_permissions", relevantPermissionsList)
		if err != nil {
			return err
		}
	}
	if rOut.GithubInstallationTokenRepositories != nil {
		err = d.Set("token_repositories", *rOut.GithubInstallationTokenRepositories)
		if err != nil {
			return err
		}
	}

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

func removeIgnoredEntriesFromList(origMap map[string]string, list []string) []string {
	destMap := listToMap(list)

	mapFields := []string{"contents", "actions", "issues", "metadata"}

	for _, field := range mapFields {
		if _, ok := destMap[field]; !ok {
			delete(origMap, field)
		}
	}

	relevantPermissionsList := mapToList(destMap)
	return relevantPermissionsList
}

func listToMap(permList []string) map[string]string {
	permMap := make(map[string]string)
	for _, val := range permList {
		splitedPerm := strings.Split(val, "=")
		permMap[splitedPerm[0]] = splitedPerm[1]
	}
	return permMap
}

func mapToList(permMap map[string]string) []string {
	list := make([]string, 0, len(permMap))
	for key, val := range permMap {
		list = append(list, fmt.Sprintf("%v=%v", key, val))
	}
	return list
}
