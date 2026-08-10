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
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("bearer_token"), cty.GetAttrPath("bearer_token_wo")),
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
			"bearer_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Bearer token value",
			},
			"bearer_token_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"bearer_token_wo_version"},
				WriteOnly:    true,
				Description:  "bearer_token (write-only, not stored in state). Requires Terraform 1.11+. Bump bearer_token_wo_version to change it.",
			},
			"bearer_token_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"bearer_token_wo"},
				Description:  "Version trigger for bearer_token_wo. Increment to update the value.",
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
	bearerToken, err := common.EffectiveSecretValue(d, "bearer_token", "bearer_token_wo")
	if err != nil {
		return err
	}
	common.GetAkeylessPtr(&body.BearerToken, bearerToken)
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
	return nil
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
		if err := common.SetSecretFromRead(d, "bearer_token", "bearer_token_wo", "bearer_token_wo_version", cfg.BearerToken); err != nil {
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

	if d.HasChanges("url", "bearer_token", "protection_key", "keep_prev_version", "input_rule", "output_rule", "bearer_token_wo_version") {
		body := akeyless_api.UpdateMcpSecretBearerToken{
			Name:  name,
			Token: &token,
		}
		common.GetAkeylessPtr(&body.Url, d.Get("url").(string))
		bearerToken, err := common.SecretValueForUpdate(d, "bearer_token", "bearer_token_wo")
		if err != nil {
			return err
		}
		common.SetOptionalString(&body.BearerToken, bearerToken)
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
	d.SetId(name)
	return nil
}
