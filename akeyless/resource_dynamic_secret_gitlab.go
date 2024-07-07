package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretGitlab() *schema.Resource {
	return &schema.Resource{
		Description: "Gitlab dynamic secret resource.",
		Create:      resourceDynamicSecretGitlabCreate,
		Read:        resourceDynamicSecretGitlabRead,
		Update:      resourceDynamicSecretGitlabUpdate,
		Delete:      resourceDynamicSecretGitlabDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretGitlabImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Name of an existing target",
			},
			"gitlab_access_type": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Gitlab access token type [project,group]",
			},
			"installation_organization": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Gitlab project name, required for access-type=project",
			},
			"group_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Gitlab group name, required for access-type=group",
			},
			"gitlab_role": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Gitlab role",
				Default:     "GuestPermissions",
			},
			"gitlab_token_scopes": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Comma-separated list of access token scopes to grant",
			},
			"ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Access Token TTL",
				Default:     "60m",
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
			"tags": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "Add tags attached to this object. To specify multiple tags use argument multiple times: --tag Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"description": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Description of the object",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Protection from accidental deletion of this item, [true/false]",
			},
		},
	}
}

func resourceDynamicSecretGitlabCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	gitlabAccessType := d.Get("gitlab_access_type").(string)
	installationOrganization := d.Get("installation_organization").(string)
	groupName := d.Get("group_name").(string)
	gitlabRole := d.Get("gitlab_role").(string)
	gitlabTokenScopes := d.Get("gitlab_token_scopes").(string)
	ttl := d.Get("ttl").(string)
	gitlabAccessToken := d.Get("gitlab_access_token").(string)
	gitlabCertificate := d.Get("gitlab_certificate").(string)
	gitlabUrl := d.Get("gitlab_url").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.DynamicSecretCreateGitlab{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.GitlabAccessType, gitlabAccessType)
	common.GetAkeylessPtr(&body.InstallationOrganization, installationOrganization)
	common.GetAkeylessPtr(&body.GroupName, groupName)
	common.GetAkeylessPtr(&body.GitlabRole, gitlabRole)
	common.GetAkeylessPtr(&body.GitlabTokenScopes, gitlabTokenScopes)
	common.GetAkeylessPtr(&body.Ttl, ttl)
	common.GetAkeylessPtr(&body.GitlabAccessToken, gitlabAccessToken)
	common.GetAkeylessPtr(&body.GitlabCertificate, gitlabCertificate)
	common.GetAkeylessPtr(&body.GitlabUrl, gitlabUrl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.DynamicSecretCreateGitlab(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretGitlabRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
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
	if rOut.GitlabAccessType != nil {
		err = d.Set("gitlab_access_type", *rOut.GitlabAccessType)
		if err != nil {
			return err
		}
	}
	if rOut.GitlabRole != nil {
		err = d.Set("gitlab_role", *rOut.GitlabRole)
		if err != nil {
			return err
		}
	}
	if rOut.GitlabAccessToken != nil {
		err = d.Set("gitlab_access_token", *rOut.GitlabAccessToken)
		if err != nil {
			return err
		}
	}
	if rOut.GitlabCertificate != nil {
		err = d.Set("gitlab_certificate", *rOut.GitlabCertificate)
		if err != nil {
			return err
		}
	}
	if rOut.GitlabUrl != nil {
		err = d.Set("gitlab_url", *rOut.GitlabUrl)
		if err != nil {
			return err
		}
	}
	if rOut.Tags != nil {
		err = d.Set("tags", *rOut.Tags)
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
	if rOut.GitlabProjectName != nil {
		err = d.Set("installation_organization", *rOut.GitlabProjectName)
		if err != nil {
			return err
		}
	}
	if rOut.GitlabGroupName != nil {
		err = d.Set("group_name", *rOut.GitlabGroupName)
		if err != nil {
			return err
		}
	}
	if rOut.GitlabTokenScope != nil {
		err = d.Set("gitlab_token_scopes", strings.Join(*rOut.GitlabTokenScope, ","))
		if err != nil {
			return err
		}
	}
	if rOut.UserTtl != nil {
		err = d.Set("ttl", *rOut.UserTtl)
		if err != nil {
			return err
		}
	}
	if rOut.DeleteProtection != nil {
		err = d.Set("delete_protection", strconv.FormatBool(*rOut.DeleteProtection))
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceDynamicSecretGitlabUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	gitlabAccessType := d.Get("gitlab_access_type").(string)
	installationOrganization := d.Get("installation_organization").(string)
	groupName := d.Get("group_name").(string)
	gitlabRole := d.Get("gitlab_role").(string)
	gitlabTokenScopes := d.Get("gitlab_token_scopes").(string)
	ttl := d.Get("ttl").(string)
	gitlabAccessToken := d.Get("gitlab_access_token").(string)
	gitlabCertificate := d.Get("gitlab_certificate").(string)
	gitlabUrl := d.Get("gitlab_url").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.DynamicSecretUpdateGitlab{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.GitlabAccessType, gitlabAccessType)
	common.GetAkeylessPtr(&body.InstallationOrganization, installationOrganization)
	common.GetAkeylessPtr(&body.GroupName, groupName)
	common.GetAkeylessPtr(&body.GitlabRole, gitlabRole)
	common.GetAkeylessPtr(&body.GitlabTokenScopes, gitlabTokenScopes)
	common.GetAkeylessPtr(&body.Ttl, ttl)
	common.GetAkeylessPtr(&body.GitlabAccessToken, gitlabAccessToken)
	common.GetAkeylessPtr(&body.GitlabCertificate, gitlabCertificate)
	common.GetAkeylessPtr(&body.GitlabUrl, gitlabUrl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.DynamicSecretUpdateGitlab(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretGitlabDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretGitlabImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()

	err := resourceDynamicSecretGitlabRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
