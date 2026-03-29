package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretGithub() *schema.Resource {
	return &schema.Resource{
		Description: "Github dynamic secret resource",
		Create:      resourceDynamicSecretGithubCreate,
		Read:        resourceDynamicSecretGithubRead,
		Update:      resourceDynamicSecretGithubUpdate,
		Delete:      resourceDynamicSecretGithubDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretGithubImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"installation_id": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "GitHub application installation id",
			},
			"installation_organization": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional, mutually exclusive with installation id, GitHub organization name",
			},
			"installation_repository": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional, mutually exclusive with installation id, GitHub repository '<owner>/<repo-name>'",
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Target name",
			},
			"github_app_id": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Github app id",
			},
			"github_app_private_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "App private key",
			},
			"github_base_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base URL",
				Default:     "https://api.github.com/",
			},
			"token_permissions": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Optional - installation token's allowed permissions",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"token_repositories": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Optional - installation token's allowed repositories",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"token_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Token TTL",
				Default:     "60m",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceDynamicSecretGithubCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	installationId := d.Get("installation_id").(int)
	installationOrganization := d.Get("installation_organization").(string)
	installationRepository := d.Get("installation_repository").(string)
	targetName := d.Get("target_name").(string)
	githubAppId := d.Get("github_app_id").(int)
	githubAppPrivateKey := d.Get("github_app_private_key").(string)
	githubBaseUrl := d.Get("github_base_url").(string)
	tokenPermissionsSet := d.Get("token_permissions").(*schema.Set)
	tokenPermissions := common.ExpandStringList(tokenPermissionsSet.List())
	tokenRepositoriesSet := d.Get("token_repositories").(*schema.Set)
	tokenRepositories := common.ExpandStringList(tokenRepositoriesSet.List())
	tokenTtl := d.Get("token_ttl").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.DynamicSecretCreateGithub{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.InstallationId, installationId)
	common.GetAkeylessPtr(&body.InstallationOrganization, installationOrganization)
	common.GetAkeylessPtr(&body.InstallationRepository, installationRepository)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.GithubAppId, githubAppId)
	common.GetAkeylessPtr(&body.GithubAppPrivateKey, githubAppPrivateKey)
	common.GetAkeylessPtr(&body.GithubBaseUrl, githubBaseUrl)
	common.GetAkeylessPtr(&body.TokenPermissions, tokenPermissions)
	common.GetAkeylessPtr(&body.TokenRepositories, tokenRepositories)
	common.GetAkeylessPtr(&body.TokenTtl, tokenTtl)
	if len(itemCustomFields) > 0 {
		customFieldsMap := make(map[string]string)
		for k, v := range itemCustomFields {
			customFieldsMap[k] = v.(string)
		}
		body.ItemCustomFields = &customFieldsMap
	}

	_, resp, err := client.DynamicSecretCreateGithub(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretGithubRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get dynamic secret value", res, err)
	}
	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}
	if rOut.Metadata != nil {
		err = d.Set("description", *rOut.Metadata)
		if err != nil {
			return err
		}
	}
	if rOut.Tags != nil {
		err = d.Set("tags", rOut.Tags)
		if err != nil {
			return err
		}
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

	// Akeyless might return more than one installation, but we will update only if we work appropriately with one installation.
	// installation_id is relevant when installation_organization and installation_repository aren't (need exactly one)
	if rOut.GithubInstallationId != nil {
		if d.Get("installation_repository").(string) == "" && d.Get("installation_organization").(string) == "" {
			err = d.Set("installation_id", *rOut.GithubInstallationId)
			if err != nil {
				return err
			}
		}
	}
	// installation_organization is relevant when installation_id and installation_repository aren't (need exactly one)
	if rOut.GithubOrganizationName != nil {
		if d.Get("installation_id").(int) == 0 && d.Get("installation_repository").(string) == "" {
			err = d.Set("installation_organization", *rOut.GithubOrganizationName)
			if err != nil {
				return err
			}
		}
	}
	// installation_repository is relevant when installation_id and installation_organization aren't (need exactly one)
	if rOut.GithubRepositoryPath != nil {
		if d.Get("installation_id").(int) == 0 && d.Get("installation_organization").(string) == "" {
			err = d.Set("installation_repository", *rOut.GithubRepositoryPath)
			if err != nil {
				return err
			}
		}
	}

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = common.SetDataByPrefixSlash(d, "target_name", targetName, d.Get("target_name").(string))
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
		err = d.Set("token_repositories", rOut.GithubInstallationTokenRepositories)
		if err != nil {
			return err
		}
	}

	if rOut.UserTtl != nil {
		err = d.Set("token_ttl", *rOut.UserTtl)
		if err != nil {
			return err
		}
	}

	if rOut.ItemCustomFieldsDetails != nil && len(rOut.ItemCustomFieldsDetails) > 0 {
		customFields := make(map[string]string)
		for _, field := range rOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		if len(customFields) > 0 {
			err = d.Set("item_custom_fields", customFields)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceDynamicSecretGithubUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	installationId := d.Get("installation_id").(int)
	installationOrganization := d.Get("installation_organization").(string)
	installationRepository := d.Get("installation_repository").(string)
	targetName := d.Get("target_name").(string)
	githubAppId := d.Get("github_app_id").(int)
	githubAppPrivateKey := d.Get("github_app_private_key").(string)
	githubBaseUrl := d.Get("github_base_url").(string)
	tokenPermissionsSet := d.Get("token_permissions").(*schema.Set)
	tokenPermissions := common.ExpandStringList(tokenPermissionsSet.List())
	tokenRepositoriesSet := d.Get("token_repositories").(*schema.Set)
	tokenRepositories := common.ExpandStringList(tokenRepositoriesSet.List())
	tokenTtl := d.Get("token_ttl").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.DynamicSecretUpdateGithub{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.InstallationId, installationId)
	common.GetAkeylessPtr(&body.InstallationOrganization, installationOrganization)
	common.GetAkeylessPtr(&body.InstallationRepository, installationRepository)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.GithubAppId, githubAppId)
	common.GetAkeylessPtr(&body.GithubAppPrivateKey, githubAppPrivateKey)
	common.GetAkeylessPtr(&body.GithubBaseUrl, githubBaseUrl)
	common.GetAkeylessPtr(&body.TokenPermissions, tokenPermissions)
	common.GetAkeylessPtr(&body.TokenRepositories, tokenRepositories)
	common.GetAkeylessPtr(&body.TokenTtl, tokenTtl)
	if len(itemCustomFields) > 0 {
		customFieldsMap := make(map[string]string)
		for k, v := range itemCustomFields {
			customFieldsMap[k] = v.(string)
		}
		body.ItemCustomFields = &customFieldsMap
	}

	_, resp, err := client.DynamicSecretUpdateGithub(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretGithubDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretGithubImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretGithubRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
