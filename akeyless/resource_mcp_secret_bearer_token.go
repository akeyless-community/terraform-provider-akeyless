// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceMcpSecretBearerToken() *schema.Resource {
	return &schema.Resource{
		Description: "MCP secret using Bearer Token authentication",
		Create:      resourceMcpSecretBearerTokenCreate,
		Read:        resourceMcpSecretBearerTokenRead,
		Update:      resourceMcpSecretBearerTokenUpdate,
		Delete:      resourceMcpSecretDelete,
		Importer: &schema.ResourceImporter{
			State: resourceMcpSecretImport,
		},
		Schema: mcpSecretCommonSchema(map[string]*schema.Schema{
			"bearer_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Bearer token value",
			},
		}),
	}
}

func resourceMcpSecretBearerTokenCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.CreateMcpSecretBearerToken{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Url, d.Get("url").(string))
	common.GetAkeylessPtr(&body.BearerToken, d.Get("bearer_token").(string))
	common.GetAkeylessPtr(&body.ProtectionKey, d.Get("protection_key").(string))
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.Accessibility, d.Get("accessibility").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.InputRule, expandOptionalStringList(d, "input_rule"))
	common.GetAkeylessPtr(&body.OutputRule, expandOptionalStringList(d, "output_rule"))
	common.GetAkeylessPtr(&body.Tags, expandOptionalStringSet(d, "tags"))

	_, resp, err := client.CreateMcpSecretBearerToken(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create MCP secret bearer token", resp, err)
	}

	d.SetId(name)
	return resourceMcpSecretBearerTokenRead(d, m)
}

func resourceMcpSecretBearerTokenRead(d *schema.ResourceData, m interface{}) error {
	cfg, itemOut, err := readMcpSecretValue(d, m)
	if err != nil {
		return err
	}
	if cfg != nil {
		if err := d.Set("url", cfg.URL); err != nil {
			return err
		}
		if err := d.Set("bearer_token", cfg.BearerToken); err != nil {
			return err
		}
	}
	return setMcpSecretCommonReadFields(d, itemOut)
}

func resourceMcpSecretBearerTokenUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	name := d.Id()

	if d.HasChanges("url", "bearer_token", "protection_key", "keep_prev_version", "input_rule", "output_rule") {
		body := akeyless_api.UpdateMcpSecretBearerToken{
			Name:  name,
			Token: &token,
		}
		common.GetAkeylessPtr(&body.Url, d.Get("url").(string))
		common.GetAkeylessPtr(&body.BearerToken, d.Get("bearer_token").(string))
		common.GetAkeylessPtr(&body.Key, d.Get("protection_key").(string))
		common.GetAkeylessPtr(&body.KeepPrevVersion, d.Get("keep_prev_version").(string))
		common.GetAkeylessPtr(&body.InputRule, expandOptionalStringList(d, "input_rule"))
		common.GetAkeylessPtr(&body.OutputRule, expandOptionalStringList(d, "output_rule"))

		_, resp, err := client.UpdateMcpSecretBearerToken(ctx).Body(body).Execute()
		if err != nil {
			return common.HandleError("can't update MCP secret bearer token", resp, err)
		}
	}

	if err := updateMcpSecretItemMeta(d, m); err != nil {
		return err
	}
	return resourceMcpSecretBearerTokenRead(d, m)
}
