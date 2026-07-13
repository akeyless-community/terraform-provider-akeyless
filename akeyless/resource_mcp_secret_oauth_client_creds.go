// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceMcpSecretOAuthClientCreds() *schema.Resource {
	return &schema.Resource{
		Description: "MCP secret using OAuth 2.0 Client Credentials authentication",
		Create:      resourceMcpSecretOAuthClientCredsCreate,
		Read:        resourceMcpSecretOAuthClientCredsRead,
		Update:      resourceMcpSecretOAuthClientCredsUpdate,
		Delete:      resourceMcpSecretDelete,
		Importer: &schema.ResourceImporter{
			State: resourceMcpSecretImport,
		},
		Schema: mcpSecretCommonSchema(mcpSecretOAuthBaseSchema()),
	}
}

func resourceMcpSecretOAuthClientCredsCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.CreateMcpSecretOAuthClientCreds{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Url, d.Get("url").(string))
	common.GetAkeylessPtr(&body.OauthClientId, d.Get("oauth_client_id").(string))
	common.GetAkeylessPtr(&body.OauthClientSecret, d.Get("oauth_client_secret").(string))
	common.GetAkeylessPtr(&body.OauthTokenUrl, d.Get("oauth_token_url").(string))
	common.GetAkeylessPtr(&body.OauthScopes, expandOptionalStringList(d, "oauth_scopes"))
	common.GetAkeylessPtr(&body.ProtectionKey, d.Get("protection_key").(string))
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Accessibility, d.Get("accessibility").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.InputRule, expandOptionalStringList(d, "input_rule"))
	common.GetAkeylessPtr(&body.OutputRule, expandOptionalStringList(d, "output_rule"))
	common.GetAkeylessPtr(&body.Tags, expandOptionalStringSet(d, "tags"))

	_, resp, err := client.CreateMcpSecretOAuthClientCreds(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create MCP secret oauth client credentials", resp, err)
	}

	d.SetId(name)
	return resourceMcpSecretOAuthClientCredsRead(d, m)
}

func resourceMcpSecretOAuthClientCredsRead(d *schema.ResourceData, m interface{}) error {
	cfg, itemOut, err := readMcpSecretValue(d, m)
	if err != nil {
		return err
	}
	if cfg != nil {
		if err := setMcpSecretOAuthReadFields(d, cfg); err != nil {
			return err
		}
	}
	return setMcpSecretCommonReadFields(d, itemOut)
}

func resourceMcpSecretOAuthClientCredsUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Id()

	if d.HasChanges("url", "oauth_client_id", "oauth_client_secret", "oauth_token_url", "oauth_scopes", "protection_key", "keep_prev_version", "input_rule", "output_rule") {
		body := akeyless_api.UpdateMcpSecretOAuthClientCreds{
			Name:  name,
			Token: &token,
		}
		common.GetAkeylessPtr(&body.Url, d.Get("url").(string))
		common.GetAkeylessPtr(&body.OauthClientId, d.Get("oauth_client_id").(string))
		common.GetAkeylessPtr(&body.OauthClientSecret, d.Get("oauth_client_secret").(string))
		common.GetAkeylessPtr(&body.OauthTokenUrl, d.Get("oauth_token_url").(string))
		common.GetAkeylessPtr(&body.OauthScopes, expandOptionalStringList(d, "oauth_scopes"))
		common.GetAkeylessPtr(&body.Key, d.Get("protection_key").(string))
		common.GetAkeylessPtr(&body.KeepPrevVersion, d.Get("keep_prev_version").(string))
		common.GetAkeylessPtr(&body.InputRule, expandOptionalStringList(d, "input_rule"))
		common.GetAkeylessPtr(&body.OutputRule, expandOptionalStringList(d, "output_rule"))

		_, resp, err := client.UpdateMcpSecretOAuthClientCreds(ctx).Body(body).Execute()
		if err != nil {
			return common.HandleError("can't update MCP secret oauth client credentials", resp, err)
		}
	}

	if err := updateMcpSecretItemMeta(d, m); err != nil {
		return err
	}
	return resourceMcpSecretOAuthClientCredsRead(d, m)
}
