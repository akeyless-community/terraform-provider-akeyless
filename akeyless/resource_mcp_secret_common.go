package akeyless

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type mcpSecretAuthConfig struct {
	URL          string `json:"url"`
	Type         string `json:"type"`
	BearerToken  string `json:"bearer_token,omitempty"`
	ClientID     string `json:"oauth_client_id,omitempty"`
	ClientSecret string `json:"oauth_client_secret,omitempty"`
	TokenURL     string `json:"oauth_token_url,omitempty"`
	Scopes       string `json:"oauth_scopes,omitempty"`
	RedirectURI  string `json:"oauth_redirect_uri,omitempty"`
	RefreshToken string `json:"oauth_refresh_token,omitempty"`
}

func mcpSecretCommonSchema(extra map[string]*schema.Schema) map[string]*schema.Schema {
	schemaMap := map[string]*schema.Schema{
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
	}
	for k, v := range extra {
		schemaMap[k] = v
	}
	return schemaMap
}

func mcpSecretOAuthBaseSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
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
	}
}

func mergeSchemaMaps(maps ...map[string]*schema.Schema) map[string]*schema.Schema {
	out := map[string]*schema.Schema{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func expandOptionalStringList(d *schema.ResourceData, key string) []string {
	raw, ok := d.Get(key).([]interface{})
	if !ok {
		return nil
	}
	return common.ExpandStringList(raw)
}

func expandOptionalStringSet(d *schema.ResourceData, key string) []string {
	set, ok := d.Get(key).(*schema.Set)
	if !ok || set == nil {
		return nil
	}
	return common.ExpandStringList(set.List())
}

func readMcpSecretValue(d *schema.ResourceData, m interface{}) (*mcpSecretAuthConfig, *akeyless_api.Item, error) {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	path := d.Id()
	ctx := context.Background()

	gsvBody := akeyless_api.GetSecretValue{
		Names: []string{path},
		Token: &token,
	}
	gsvOut, res, err := client.GetSecretValue(ctx).Body(gsvBody).Execute()
	if err != nil {
		return nil, nil, common.HandleReadError(d, "can't get MCP secret value", res, err)
	}

	item := akeyless_api.DescribeItem{
		Name:  path,
		Token: &token,
	}
	itemOut, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return nil, nil, err
	}

	value, ok := gsvOut[path]
	if !ok {
		return nil, itemOut, fmt.Errorf("MCP secret value missing for %s", path)
	}
	stringValue, ok := value.(string)
	if !ok {
		return nil, itemOut, fmt.Errorf("wrong MCP secret value type")
	}

	var cfg mcpSecretAuthConfig
	if err := json.Unmarshal([]byte(stringValue), &cfg); err != nil {
		return nil, itemOut, fmt.Errorf("can't parse MCP secret value: %w", err)
	}
	return &cfg, itemOut, nil
}

func setMcpSecretCommonReadFields(d *schema.ResourceData, itemOut *akeyless_api.Item) error {
	if itemOut == nil {
		return nil
	}
	if itemOut.ProtectionKeyName != nil {
		if err := d.Set("protection_key", *itemOut.ProtectionKeyName); err != nil {
			return err
		}
	}
	if itemOut.ItemMetadata != nil {
		if err := d.Set("description", *itemOut.ItemMetadata); err != nil {
			return err
		}
	}
	if itemOut.ItemTags != nil {
		if err := d.Set("tags", itemOut.ItemTags); err != nil {
			return err
		}
	}
	deleteProtectionVal := "false"
	if itemOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*itemOut.DeleteProtection)
	}
	if err := d.Set("delete_protection", deleteProtectionVal); err != nil {
		return err
	}
	if itemOut.ItemGeneralInfo != nil {
		if err := setAgenticRulesReadFields(d, itemOut.ItemGeneralInfo.AgenticRules); err != nil {
			return err
		}
	}
	return nil
}

func setMcpSecretOAuthReadFields(d *schema.ResourceData, cfg *mcpSecretAuthConfig) error {
	if err := d.Set("url", cfg.URL); err != nil {
		return err
	}
	if err := d.Set("oauth_client_id", cfg.ClientID); err != nil {
		return err
	}
	if err := d.Set("oauth_client_secret", cfg.ClientSecret); err != nil {
		return err
	}
	if err := d.Set("oauth_token_url", cfg.TokenURL); err != nil {
		return err
	}
	scopes := []string{}
	if strings.TrimSpace(cfg.Scopes) != "" {
		scopes = strings.Fields(cfg.Scopes)
	}
	if err := d.Set("oauth_scopes", scopes); err != nil {
		return err
	}
	return nil
}

func updateMcpSecretItemMeta(d *schema.ResourceData, m interface{}) error {
	if !d.HasChanges("description", "tags", "delete_protection", "max_versions") {
		return nil
	}

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()
	path := d.Id()

	bodyItem := akeyless_api.UpdateItem{
		Name:    path,
		NewName: akeyless_api.PtrString(path),
		Token:   &token,
	}
	tags := expandOptionalStringSet(d, "tags")
	add, remove, err := common.GetTagsForUpdate(d, path, token, tags, client)
	if err == nil {
		if len(add) > 0 {
			common.GetAkeylessPtr(&bodyItem.AddTag, add)
		}
		if len(remove) > 0 {
			common.GetAkeylessPtr(&bodyItem.RmTag, remove)
		}
	}
	common.GetAkeylessPtr(&bodyItem.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&bodyItem.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&bodyItem.MaxVersions, d.Get("max_versions").(string))

	_, resp, err := client.UpdateItem(ctx).Body(bodyItem).Execute()
	if err != nil {
		return common.HandleError("can't update MCP secret metadata", resp, err)
	}
	return nil
}

func resourceMcpSecretDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()

	path := d.Id()
	deleteItem := akeyless_api.DeleteItem{
		Name:  path,
		Token: &token,
	}
	_, _, err := client.DeleteItem(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}
	return nil
}

func resourceMcpSecretImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	err := d.Set("name", d.Id())
	if err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
