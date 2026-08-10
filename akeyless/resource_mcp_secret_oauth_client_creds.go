// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
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
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("oauth_client_secret"), cty.GetAttrPath("oauth_client_secret_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				Description:      "Secret name",
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL of the MCP service",
			},
			"oauth_client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "OAuth client ID",
			},
			"oauth_client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "OAuth client secret",
			},
			"oauth_client_secret_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"oauth_client_secret_wo_version"},
				WriteOnly:    true,
				Description:  "oauth_client_secret (write-only, not stored in state). Requires Terraform 1.11+. Bump oauth_client_secret_wo_version to change it.",
			},
			"oauth_client_secret_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"oauth_client_secret_wo"},
				Description:  "Version trigger for oauth_client_secret_wo. Increment to update the value.",
			},
			"oauth_token_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "OAuth token URL",
			},
			"oauth_scopes": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "OAuth scopes",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"accessibility": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "For personal password manager",
				Default:     "regular",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"protection_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that is used to encrypt the secret value (if empty, the account default protectionKey key will be used)",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"input_rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Agentic input rule in name=...,rule=... format",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"output_rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Agentic output rule in name=...,rule=... format",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
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
	oauthClientSecret, err := common.EffectiveSecretValue(d, "oauth_client_secret", "oauth_client_secret_wo")
	if err != nil {
		return err
	}
	common.GetAkeylessPtr(&body.OauthClientSecret, oauthClientSecret)
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
	return nil
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

	if d.HasChanges("url", "oauth_client_id", "oauth_client_secret", "oauth_token_url", "oauth_scopes", "protection_key", "keep_prev_version", "input_rule", "output_rule", "oauth_client_secret_wo_version") {
		body := akeyless_api.UpdateMcpSecretOAuthClientCreds{
			Name:  name,
			Token: &token,
		}
		common.GetAkeylessPtr(&body.Url, d.Get("url").(string))
		common.GetAkeylessPtr(&body.OauthClientId, d.Get("oauth_client_id").(string))
		oauthClientSecret, err := common.SecretValueForUpdate(d, "oauth_client_secret", "oauth_client_secret_wo")
		if err != nil {
			return err
		}
		common.SetOptionalString(&body.OauthClientSecret, oauthClientSecret)
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
	d.SetId(name)
	return nil
}
