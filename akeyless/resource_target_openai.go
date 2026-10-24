package akeyless

import (
	"context"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const codexOauthModeChatGPT = "chatgpt_oauth"

func resourceOpenAITarget() *schema.Resource {
	return &schema.Resource{
		Description:   "OpenAI Target resource. In ChatGPT OAuth mode, every update requires a new Codex refresh token",
		Create:        resourceOpenAITargetCreate,
		Read:          resourceOpenAITargetRead,
		Update:        resourceOpenAITargetUpdate,
		Delete:        resourceOpenAITargetDelete,
		CustomizeDiff: resourceOpenAITargetCustomizeDiff,
		Importer: &schema.ResourceImporter{
			State: resourceOpenAITargetImport,
		},
		Schema: map[string]*schema.Schema{
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
			"codex_oauth_mode": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Auth mode: empty (default, static api-key) or chatgpt_oauth",
			},
			"codex_oauth_account_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Codex OAuth account id (auth.json tokens.account_id), used when codex_oauth_mode=chatgpt_oauth",
			},
			"codex_oauth_access_token_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Description: "Codex OAuth access token (auth.json tokens.access_token), used when codex_oauth_mode=chatgpt_oauth. Optional, the gateway populates it during refresh. Write-only, not stored in state; sent only when codex_oauth_token_wo_version changes. Requires Terraform 1.11 or later",
			},
			"codex_oauth_refresh_token_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				WriteOnly:   true,
				Description: "Codex OAuth refresh token (auth.json tokens.refresh_token), required when codex_oauth_mode=chatgpt_oauth. Write-only, not stored in state; sent only when codex_oauth_token_wo_version changes. The gateway rotates this token during use, so every update in chatgpt_oauth mode requires a new refresh token (for example, from a new codex login). Do not keep using the same Codex session locally. Requires Terraform 1.11 or later",
			},
			"codex_oauth_token_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version of the Codex OAuth write-only tokens. Change it to send new codex_oauth_refresh_token_wo and codex_oauth_access_token_wo values. In chatgpt_oauth mode, every update requires a new version",
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
	model := d.Get("model").(string)
	openaiUrl := d.Get("openai_url").(string)
	organizationId := d.Get("organization_id").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	codexOauthMode := d.Get("codex_oauth_mode").(string)
	codexOauthAccountId := d.Get("codex_oauth_account_id").(string)
	codexOauthAccessToken := getWriteOnlyString(d, "codex_oauth_access_token_wo")
	codexOauthRefreshToken := getWriteOnlyString(d, "codex_oauth_refresh_token_wo")

	body := akeyless_api.TargetCreateOpenAI{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.ApiKeyId, apiKeyId)
	common.GetAkeylessPtr(&body.Model, model)
	common.GetAkeylessPtr(&body.OpenaiUrl, openaiUrl)
	common.GetAkeylessPtr(&body.OrganizationId, organizationId)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.CodexOauthMode, codexOauthMode)
	common.GetAkeylessPtr(&body.CodexOauthAccountId, codexOauthAccountId)
	common.GetAkeylessPtr(&body.CodexOauthAccessToken, codexOauthAccessToken)
	common.GetAkeylessPtr(&body.CodexOauthRefreshToken, codexOauthRefreshToken)

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
		err = d.Set("codex_oauth_mode", rOut.Value.OpenaiTargetDetails.GetAuthMode())
		if err != nil {
			return err
		}
		err = d.Set("codex_oauth_account_id", rOut.Value.OpenaiTargetDetails.GetOauthAccountId())
		if err != nil {
			return err
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
	model := d.Get("model").(string)
	openaiUrl := d.Get("openai_url").(string)
	organizationId := d.Get("organization_id").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)
	codexOauthMode := d.Get("codex_oauth_mode").(string)
	codexOauthAccountId := d.Get("codex_oauth_account_id").(string)

	body := akeyless_api.TargetUpdateOpenAI{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.NewName, name)
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.ApiKeyId, apiKeyId)
	common.GetAkeylessPtr(&body.Model, model)
	common.GetAkeylessPtr(&body.OpenaiUrl, openaiUrl)
	common.GetAkeylessPtr(&body.OrganizationId, organizationId)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)
	common.GetAkeylessPtr(&body.CodexOauthMode, codexOauthMode)
	common.GetAkeylessPtr(&body.CodexOauthAccountId, codexOauthAccountId)
	if d.HasChange("codex_oauth_token_wo_version") {
		common.GetAkeylessPtr(&body.CodexOauthAccessToken, getWriteOnlyString(d, "codex_oauth_access_token_wo"))
		common.GetAkeylessPtr(&body.CodexOauthRefreshToken, getWriteOnlyString(d, "codex_oauth_refresh_token_wo"))
	}

	_, resp, err := client.TargetUpdateOpenAI(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceOpenAITargetCustomizeDiff(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
	if d.Id() == "" || d.Get("codex_oauth_mode").(string) != codexOauthModeChatGPT {
		return nil
	}
	if hasNonWriteOnlyChange(d) && !d.HasChange("codex_oauth_token_wo_version") {
		return fmt.Errorf("codex_oauth_token_wo_version must change on every update in %s mode, because the gateway rotates the refresh token. Run codex login, set the new codex_oauth_refresh_token_wo and change codex_oauth_token_wo_version", codexOauthModeChatGPT)
	}
	return nil
}

// The SDK diff lists write-only attributes as changed on every plan, because they are never stored in state.
func hasNonWriteOnlyChange(d *schema.ResourceDiff) bool {
	for _, key := range d.GetChangedKeysPrefix("") {
		if key != "codex_oauth_access_token_wo" && key != "codex_oauth_refresh_token_wo" {
			return true
		}
	}
	return false
}

func getWriteOnlyString(d *schema.ResourceData, key string) string {
	value := d.GetRawConfig().GetAttr(key)
	if !value.IsKnown() || value.IsNull() {
		return ""
	}
	return value.AsString()
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
