package akeyless

import (
	"context"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceHashiVaultTarget() *schema.Resource {
	return &schema.Resource{
		Description: "HashiCorp Vault Target resource",
		Create:      resourceHashiVaultTargetCreate,
		Read:        resourceHashiVaultTargetRead,
		Update:      resourceHashiVaultTargetUpdate,
		Delete:      resourceHashiVaultTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceHashiVaultTargetImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("vault_token"), cty.GetAttrPath("vault_token_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"hashi_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "HashiCorp Vault API URL, e.g. https://vault-mgr01:8200",
			},
			"vault_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Vault access token with sufficient permissions",
			},
			"vault_token_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "Vault access token with sufficient permissions (write-only, not stored in state). Requires Terraform 1.11+. Bump vault_token_wo_version to change it.",
			},
			"vault_token_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for vault_token_wo. Increment to update the token.",
			},
			"namespace": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Comma-separated list of vault namespaces",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that used to encrypt the target secret value (if empty, the account default protectionKey key will be used)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
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

func resourceHashiVaultTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	hashiUrl := d.Get("hashi_url").(string)
	vaultToken, err := common.EffectiveSecretValue(d, "vault_token", "vault_token_wo")
	if err != nil {
		return err
	}
	namespaceSet := d.Get("namespace").(*schema.Set)
	namespace := common.ExpandStringList(namespaceSet.List())
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.CreateHashiVaultTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.HashiUrl, hashiUrl)
	common.GetAkeylessPtr(&body.VaultToken, vaultToken)
	common.GetAkeylessPtr(&body.Namespace, namespace)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.CreateHashiVaultTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceHashiVaultTargetRead(d *schema.ResourceData, m interface{}) error {
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
		return common.HandleReadError(d, "failed to get target details", res, err)
	}

	if rOut.Value != nil {
		targetDetails := *rOut.Value

		if targetDetails.HashiVaultTargetDetails != nil {
			if targetDetails.HashiVaultTargetDetails.VaultUrl != nil {
				err := d.Set("hashi_url", *targetDetails.HashiVaultTargetDetails.VaultUrl)
				if err != nil {
					return err
				}
			}
			if targetDetails.HashiVaultTargetDetails.VaultToken != nil {
				err := common.SetSecretFromRead(d, "vault_token", "vault_token_wo", "vault_token_wo_version", *targetDetails.HashiVaultTargetDetails.VaultToken)
				if err != nil {
					return err
				}
			}
			if targetDetails.HashiVaultTargetDetails.VaultNamespaces != nil {
				// VaultNamespaces is a comma-separated string, convert to array
				namespaces := strings.Split(*targetDetails.HashiVaultTargetDetails.VaultNamespaces, ",")
				err := d.Set("namespace", namespaces)
				if err != nil {
					return err
				}
			}
		}
	}

	if rOut.Target != nil {
		target := *rOut.Target

		if target.Comment != nil {
			err := d.Set("description", *target.Comment)
			if err != nil {
				return err
			}
		}
		if target.ProtectionKeyName != nil {
			err = d.Set("key", *target.ProtectionKeyName)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceHashiVaultTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	hashiUrl := d.Get("hashi_url").(string)
	vaultToken, err := common.EffectiveSecretValue(d, "vault_token", "vault_token_wo")
	if err != nil {
		return err
	}
	namespaceSet := d.Get("namespace").(*schema.Set)
	namespace := common.ExpandStringList(namespaceSet.List())
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.UpdateHashiVaultTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.HashiUrl, hashiUrl)
	common.GetAkeylessPtr(&body.VaultToken, vaultToken)
	common.GetAkeylessPtr(&body.Namespace, namespace)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.UpdateHashiVaultTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceHashiVaultTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceHashiVaultTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceHashiVaultTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
