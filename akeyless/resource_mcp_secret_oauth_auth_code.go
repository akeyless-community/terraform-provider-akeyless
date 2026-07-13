// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceMcpSecretOAuthAuthCode() *schema.Resource {
	return &schema.Resource{
		Description: "MCP secret using OAuth 2.0 Authorization Code authentication",
		Create:      resourceMcpSecretOAuthAuthCodeCreate,
		Read:        resourceMcpSecretOAuthAuthCodeRead,
		Update:      resourceMcpSecretOAuthAuthCodeUpdate,
		Delete:      resourceMcpSecretDelete,
		Importer: &schema.ResourceImporter{
			State: resourceMcpSecretImport,
		},
		Schema: mcpSecretCommonSchema(mergeSchemaMaps(mcpSecretOAuthBaseSchema(), map[string]*schema.Schema{
			"oauth_redirect_uri": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "OAuth redirect URI",
			},
			"oauth_refresh_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "OAuth refresh token",
			},
		})),
	}
}

func resourceMcpSecretOAuthAuthCodeCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.CreateMcpSecretOAuthAuthCode{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Url, d.Get("url").(string))
	common.GetAkeylessPtr(&body.OauthClientId, d.Get("oauth_client_id").(string))
	common.GetAkeylessPtr(&body.OauthClientSecret, d.Get("oauth_client_secret").(string))
	common.GetAkeylessPtr(&body.OauthTokenUrl, d.Get("oauth_token_url").(string))
	common.GetAkeylessPtr(&body.OauthScopes, expandOptionalStringList(d, "oauth_scopes"))
	common.GetAkeylessPtr(&body.OauthRedirectUri, d.Get("oauth_redirect_uri").(string))
	common.GetAkeylessPtr(&body.OauthRefreshToken, d.Get("oauth_refresh_token").(string))
	common.GetAkeylessPtr(&body.ProtectionKey, d.Get("protection_key").(string))
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Accessibility, d.Get("accessibility").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.InputRule, expandOptionalStringList(d, "input_rule"))
	common.GetAkeylessPtr(&body.OutputRule, expandOptionalStringList(d, "output_rule"))
	common.GetAkeylessPtr(&body.Tags, expandOptionalStringSet(d, "tags"))

	_, resp, err := client.CreateMcpSecretOAuthAuthCode(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create MCP secret oauth authorization code", resp, err)
	}

	d.SetId(name)
	return resourceMcpSecretOAuthAuthCodeRead(d, m)
}

func resourceMcpSecretOAuthAuthCodeRead(d *schema.ResourceData, m interface{}) error {
	cfg, itemOut, err := readMcpSecretValue(d, m)
	if err != nil {
		return err
	}
	if cfg != nil {
		if err := setMcpSecretOAuthReadFields(d, cfg); err != nil {
			return err
		}
		if err := d.Set("oauth_redirect_uri", cfg.RedirectURI); err != nil {
			return err
		}
		if err := d.Set("oauth_refresh_token", cfg.RefreshToken); err != nil {
			return err
		}
	}
	return setMcpSecretCommonReadFields(d, itemOut)
}

func resourceMcpSecretOAuthAuthCodeUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Id()

	if d.HasChanges("url", "oauth_client_id", "oauth_client_secret", "oauth_token_url", "oauth_scopes", "oauth_redirect_uri", "oauth_refresh_token", "protection_key", "keep_prev_version", "input_rule", "output_rule") {
		body := akeyless_api.UpdateMcpSecretOAuthAuthCode{
			Name:  name,
			Token: &token,
		}
		common.GetAkeylessPtr(&body.Url, d.Get("url").(string))
		common.GetAkeylessPtr(&body.OauthClientId, d.Get("oauth_client_id").(string))
		common.GetAkeylessPtr(&body.OauthClientSecret, d.Get("oauth_client_secret").(string))
		common.GetAkeylessPtr(&body.OauthTokenUrl, d.Get("oauth_token_url").(string))
		common.GetAkeylessPtr(&body.OauthScopes, expandOptionalStringList(d, "oauth_scopes"))
		common.GetAkeylessPtr(&body.OauthRedirectUri, d.Get("oauth_redirect_uri").(string))
		common.GetAkeylessPtr(&body.OauthRefreshToken, d.Get("oauth_refresh_token").(string))
		common.GetAkeylessPtr(&body.Key, d.Get("protection_key").(string))
		common.GetAkeylessPtr(&body.KeepPrevVersion, d.Get("keep_prev_version").(string))
		common.GetAkeylessPtr(&body.InputRule, expandOptionalStringList(d, "input_rule"))
		common.GetAkeylessPtr(&body.OutputRule, expandOptionalStringList(d, "output_rule"))

		_, resp, err := client.UpdateMcpSecretOAuthAuthCode(ctx).Body(body).Execute()
		if err != nil {
			return common.HandleError("can't update MCP secret oauth authorization code", resp, err)
		}
	}

	if err := updateMcpSecretItemMeta(d, m); err != nil {
		return err
	}
	return resourceMcpSecretOAuthAuthCodeRead(d, m)
}
