package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceOpenAITarget() *schema.Resource {
	return &schema.Resource{
		Description: "OpenAI Target resource",
		Create:      resourceOpenAITargetCreate,
		Read:        resourceOpenAITargetRead,
		Update:      resourceOpenAITargetUpdate,
		Delete:      resourceOpenAITargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceOpenAITargetImport,
		},
		Schema: map[string]*schema.Schema{
			"lock_on_read":     {Type: schema.TypeString, Optional: true, Description: "Lock after read"},
			"lock_ttl":         {Type: schema.TypeString, Optional: true, Description: "Lock TTL in minutes"},
			"rotate_on_unlock": {Type: schema.TypeString, Optional: true, Description: "Rotate after unlock"},

			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "API key for OpenAI",
			},
			"api_key_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "API key ID",
			},
			"codex_oauth_mode": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Codex OAuth authentication mode",
			},
			"codex_oauth_access_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Codex OAuth access token",
			},
			"codex_oauth_account_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Codex OAuth account ID",
			},
			"codex_oauth_refresh_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Codex OAuth refresh token",
			},
			"model": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Default model to use with OpenAI",
			},
			"openai_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base URL of the OpenAI API",
			},
			"organization_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Organization ID",
			},
			"project_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Project ID",
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
				Description: "The name of a key that used to encrypt the target secret value (if empty, the account default protectionKey key will be used)",
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

func resourceOpenAITargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	apiKey := d.Get("api_key").(string)
	apiKeyId := d.Get("api_key_id").(string)
	codexOauthMode := d.Get("codex_oauth_mode").(string)
	codexOauthAccessToken := d.Get("codex_oauth_access_token").(string)
	codexOauthAccountId := d.Get("codex_oauth_account_id").(string)
	codexOauthRefreshToken := d.Get("codex_oauth_refresh_token").(string)
	model := d.Get("model").(string)
	openaiUrl := d.Get("openai_url").(string)
	organizationId := d.Get("organization_id").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.TargetCreateOpenAI{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.ApiKeyId, apiKeyId)
	common.GetAkeylessPtr(&body.CodexOauthMode, codexOauthMode)
	common.GetAkeylessPtr(&body.CodexOauthAccessToken, codexOauthAccessToken)
	common.GetAkeylessPtr(&body.CodexOauthAccountId, codexOauthAccountId)
	common.GetAkeylessPtr(&body.CodexOauthRefreshToken, codexOauthRefreshToken)
	common.GetAkeylessPtr(&body.Model, model)
	common.GetAkeylessPtr(&body.OpenaiUrl, openaiUrl)
	common.GetAkeylessPtr(&body.OrganizationId, organizationId)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))

	_, resp, err := client.TargetCreateOpenAI(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceOpenAITargetRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.Value != nil && rOut.Value.OpenaiTargetDetails != nil {
		if rOut.Value.OpenaiTargetDetails.ApiKey != nil {
			err = d.Set("api_key", *rOut.Value.OpenaiTargetDetails.ApiKey)
			if err != nil {
				return err
			}
		}
		if rOut.Value.OpenaiTargetDetails.ApiKeyId != nil {
			err = d.Set("api_key_id", *rOut.Value.OpenaiTargetDetails.ApiKeyId)
			if err != nil {
				return err
			}
		}
		if rOut.Value.OpenaiTargetDetails.AuthMode != nil {
			err = d.Set("codex_oauth_mode", *rOut.Value.OpenaiTargetDetails.AuthMode)
			if err != nil {
				return err
			}
		}
		if rOut.Value.OpenaiTargetDetails.OauthAccessToken != nil {
			err = d.Set("codex_oauth_access_token", *rOut.Value.OpenaiTargetDetails.OauthAccessToken)
			if err != nil {
				return err
			}
		}
		if rOut.Value.OpenaiTargetDetails.OauthAccountId != nil {
			err = d.Set("codex_oauth_account_id", *rOut.Value.OpenaiTargetDetails.OauthAccountId)
			if err != nil {
				return err
			}
		}
		if rOut.Value.OpenaiTargetDetails.OauthRefreshToken != nil {
			err = d.Set("codex_oauth_refresh_token", *rOut.Value.OpenaiTargetDetails.OauthRefreshToken)
			if err != nil {
				return err
			}
		}
		if rOut.Value.OpenaiTargetDetails.OpenaiUrl != nil {
			err = d.Set("openai_url", *rOut.Value.OpenaiTargetDetails.OpenaiUrl)
			if err != nil {
				return err
			}
		}
		if rOut.Value.OpenaiTargetDetails.OrganizationId != nil {
			err = d.Set("organization_id", *rOut.Value.OpenaiTargetDetails.OrganizationId)
			if err != nil {
				return err
			}
		}
		if rOut.Value.OpenaiTargetDetails.ProjectId != nil {
			err = d.Set("project_id", *rOut.Value.OpenaiTargetDetails.ProjectId)
			if err != nil {
				return err
			}
		}
	}
	if rOut.Target != nil && rOut.Target.Comment != nil {
		err := d.Set("description", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}
	if rOut.Target != nil && rOut.Target.ProtectionKeyName != nil {
		err = d.Set("key", *rOut.Target.ProtectionKeyName)
		if err != nil {
			return err
		}
	}

	itemOut, _, err := client.DescribeItem(ctx).Body(akeyless_api.DescribeItem{Name: path, Token: &token}).Execute()
	if err != nil {
		return err
	}
	if itemOut.ItemGeneralInfo != nil {
		info := itemOut.ItemGeneralInfo
		if info.LockOnRead != nil {
			if err := d.Set("lock_on_read", strconv.FormatBool(*info.LockOnRead)); err != nil {
				return err
			}
		}
		if info.LockTtl != nil {
			if err := d.Set("lock_ttl", strconv.FormatInt(*info.LockTtl, 10)); err != nil {
				return err
			}
		}
		if info.RotateOnUnlock != nil {
			if err := d.Set("rotate_on_unlock", strconv.FormatBool(*info.RotateOnUnlock)); err != nil {
				return err
			}
		} else if info.PendingRotateOnUnlock != nil {
			if err := d.Set("rotate_on_unlock", strconv.FormatBool(*info.PendingRotateOnUnlock)); err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceOpenAITargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	apiKey := d.Get("api_key").(string)
	apiKeyId := d.Get("api_key_id").(string)
	codexOauthMode := d.Get("codex_oauth_mode").(string)
	codexOauthAccessToken := d.Get("codex_oauth_access_token").(string)
	codexOauthAccountId := d.Get("codex_oauth_account_id").(string)
	codexOauthRefreshToken := d.Get("codex_oauth_refresh_token").(string)
	model := d.Get("model").(string)
	openaiUrl := d.Get("openai_url").(string)
	organizationId := d.Get("organization_id").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.TargetUpdateOpenAI{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.NewName, name)
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.ApiKeyId, apiKeyId)
	common.GetAkeylessPtr(&body.CodexOauthMode, codexOauthMode)
	common.GetAkeylessPtr(&body.CodexOauthAccessToken, codexOauthAccessToken)
	common.GetAkeylessPtr(&body.CodexOauthAccountId, codexOauthAccountId)
	common.GetAkeylessPtr(&body.CodexOauthRefreshToken, codexOauthRefreshToken)
	common.GetAkeylessPtr(&body.Model, model)
	common.GetAkeylessPtr(&body.OpenaiUrl, openaiUrl)
	common.GetAkeylessPtr(&body.OrganizationId, organizationId)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))

	_, resp, err := client.TargetUpdateOpenAI(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceOpenAITargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceOpenAITargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceOpenAITargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
