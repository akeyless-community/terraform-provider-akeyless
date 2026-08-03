package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
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
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("gitlab_certificate"), cty.GetAttrPath("gitlab_certificate_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("gitlab_access_token"), cty.GetAttrPath("gitlab_access_token_wo")),
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
				Optional:    true,
				Sensitive:   true,
				Description: "Gitlab access token",
			},
			"gitlab_access_token_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "gitlab_access_token (write-only, not stored in state). Requires Terraform 1.11+. Bump gitlab_access_token_wo_version to change it.",
			},
			"gitlab_access_token_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for gitlab_access_token_wo. Increment to update the value.",
			},
			"gitlab_certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Gitlab tls certificate (base64 encoded)",
			},
			"gitlab_certificate_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "gitlab_certificate (write-only, not stored in state). Requires Terraform 1.11+. Bump gitlab_certificate_wo_version to change it.",
			},
			"gitlab_certificate_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for gitlab_certificate_wo. Increment to update the value.",
			},
			"gitlab_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Gitlab base url",
				Default:     "https://gitlab.com/",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used.",
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

func resourceGitlabTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	gitlabAccessToken, err := common.EffectiveSecretValue(d, "gitlab_access_token", "gitlab_access_token_wo")
	if err != nil {
		return err
	}
	gitlabCertificate, err := common.EffectiveSecretValue(d, "gitlab_certificate", "gitlab_certificate_wo")
	if err != nil {
		return err
	}
	gitlabUrl := d.Get("gitlab_url").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.TargetCreateGitlab{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GitlabAccessToken, gitlabAccessToken)
	common.GetAkeylessPtr(&body.GitlabCertificate, gitlabCertificate)
	common.GetAkeylessPtr(&body.GitlabUrl, gitlabUrl)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.TargetCreateGitlab(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceGitlabTargetRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.Value.GitlabTargetDetails.GitlabAccessToken != nil {
		err = common.SetSecretFromRead(d, "gitlab_access_token", "gitlab_access_token_wo", "gitlab_access_token_wo_version", *rOut.Value.GitlabTargetDetails.GitlabAccessToken)
		if err != nil {
			return err
		}
	}
	if rOut.Value.GitlabTargetDetails.GitlabCertificate != nil {
		err = common.SetSecretFromRead(d, "gitlab_certificate", "gitlab_certificate_wo", "gitlab_certificate_wo_version", *rOut.Value.GitlabTargetDetails.GitlabCertificate)
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
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	gitlabAccessToken, err := common.EffectiveSecretValue(d, "gitlab_access_token", "gitlab_access_token_wo")
	if err != nil {
		return err
	}
	gitlabCertificate, err := common.EffectiveSecretValue(d, "gitlab_certificate", "gitlab_certificate_wo")
	if err != nil {
		return err
	}
	gitlabUrl := d.Get("gitlab_url").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.TargetUpdateGitlab{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GitlabAccessToken, gitlabAccessToken)
	common.GetAkeylessPtr(&body.GitlabCertificate, gitlabCertificate)
	common.GetAkeylessPtr(&body.GitlabUrl, gitlabUrl)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.TargetUpdateGitlab(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceGitlabTargetDelete(d *schema.ResourceData, m interface{}) error {
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
