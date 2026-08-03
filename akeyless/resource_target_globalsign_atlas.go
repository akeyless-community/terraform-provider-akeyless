package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceGlobalsignAtlasTarget() *schema.Resource {
	return &schema.Resource{
		Description: "GlobalSign Atlas Target resource",
		Create:      resourceGlobalsignAtlasTargetCreate,
		Read:        resourceGlobalsignAtlasTargetRead,
		Update:      resourceGlobalsignAtlasTargetUpdate,
		Delete:      resourceGlobalsignAtlasTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGlobalsignAtlasTargetImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("mtls_cert_data_base64"), cty.GetAttrPath("mtls_cert_data_base64_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("api_key"), cty.GetAttrPath("api_key_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("api_secret"), cty.GetAttrPath("api_secret_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("mtls_key_data_base64"), cty.GetAttrPath("mtls_key_data_base64_wo")),
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
				Required:    true,
				Description: "API Key of the GlobalSign Atlas account",
			},
			"api_key_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "api_key (write-only, not stored in state). Requires Terraform 1.11+. Bump api_key_wo_version to change it.",
			},
			"api_key_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for api_key_wo. Increment to update the value.",
			},
			"api_secret": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "API Secret of the GlobalSign Atlas account",
			},
			"api_secret_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "API Secret of the GlobalSign Atlas account (write-only, not stored in state). Requires Terraform 1.11+. Bump api_secret_wo_version to change it.",
			},
			"api_secret_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for api_secret_wo. Increment to update the API secret.",
			},
			"mtls_cert_data_base64": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Mutual TLS Certificate contents of the GlobalSign Atlas account encoded in base64",
			},
			"mtls_cert_data_base64_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "mtls_cert_data_base64 (write-only, not stored in state). Requires Terraform 1.11+. Bump mtls_cert_data_base64_wo_version to change it.",
			},
			"mtls_cert_data_base64_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for mtls_cert_data_base64_wo. Increment to update the value.",
			},
			"mtls_key_data_base64": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Mutual TLS Key contents of the GlobalSign Atlas account encoded in base64",
			},
			"mtls_key_data_base64_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "Mutual TLS Key contents of the GlobalSign Atlas account encoded in base64 (write-only, not stored in state). Requires Terraform 1.11+. Bump mtls_key_data_base64_wo_version to change it.",
			},
			"mtls_key_data_base64_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for mtls_key_data_base64_wo. Increment to update the value.",
			},
			"timeout": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Timeout waiting for certificate validation in Duration format (1h - 1 Hour, 20m - 20 Minutes, 33m3s - 33 Minutes and 3 Seconds), maximum 1h",
				Default:          "5m",
				DiffSuppressFunc: common.DiffSuppressDuration,
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used",
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

func resourceGlobalsignAtlasTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	apiKey, err := common.EffectiveSecretValue(d, "api_key", "api_key_wo")
	if err != nil {
		return err
	}
	apiSecret, err := common.EffectiveSecretValue(d, "api_secret", "api_secret_wo")
	if err != nil {
		return err
	}
	mtlsCertDataBase64, err := common.EffectiveSecretValue(d, "mtls_cert_data_base64", "mtls_cert_data_base64_wo")
	if err != nil {
		return err
	}
	mtlsKeyDataBase64, err := common.EffectiveSecretValue(d, "mtls_key_data_base64", "mtls_key_data_base64_wo")
	if err != nil {
		return err
	}
	timeout := d.Get("timeout").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.CreateGlobalSignAtlasTarget{
		Name:      name,
		ApiKey:    apiKey,
		ApiSecret: apiSecret,
		Token:     &token,
	}
	common.GetAkeylessPtr(&body.MtlsCertDataBase64, mtlsCertDataBase64)
	common.GetAkeylessPtr(&body.MtlsKeyDataBase64, mtlsKeyDataBase64)
	common.GetAkeylessPtr(&body.Timeout, timeout)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.CreateGlobalSignAtlasTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceGlobalsignAtlasTargetRead(d *schema.ResourceData, m interface{}) error {
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

		if targetDetails.GlobalsignAtlasTargetDetails != nil {
			if targetDetails.GlobalsignAtlasTargetDetails.ApiKey != nil {
				err := common.SetSecretFromRead(d, "api_key", "api_key_wo", "api_key_wo_version", *targetDetails.GlobalsignAtlasTargetDetails.ApiKey)
				if err != nil {
					return err
				}
			}
			if targetDetails.GlobalsignAtlasTargetDetails.ApiSecret != nil {
				err := common.SetSecretFromRead(d, "api_secret", "api_secret_wo", "api_secret_wo_version", *targetDetails.GlobalsignAtlasTargetDetails.ApiSecret)
				if err != nil {
					return err
				}
			}
			if targetDetails.GlobalsignAtlasTargetDetails.MtlsCert != nil {
				err := common.SetSecretFromRead(d, "mtls_cert_data_base64", "mtls_cert_data_base64_wo", "mtls_cert_data_base64_wo_version", *targetDetails.GlobalsignAtlasTargetDetails.MtlsCert)
				if err != nil {
					return err
				}
			}
			if targetDetails.GlobalsignAtlasTargetDetails.MtlsKey != nil {
				err := common.SetSecretFromRead(d, "mtls_key_data_base64", "mtls_key_data_base64_wo", "mtls_key_data_base64_wo_version", *targetDetails.GlobalsignAtlasTargetDetails.MtlsKey)
				if err != nil {
					return err
				}
			}
			if targetDetails.GlobalsignAtlasTargetDetails.Timeout != nil {
				timeout := *targetDetails.GlobalsignAtlasTargetDetails.Timeout
				duration := common.ConvertNanoSecondsIntoDurationString(timeout)
				err := d.Set("timeout", duration)
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

func resourceGlobalsignAtlasTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	apiKey, err := common.EffectiveSecretValue(d, "api_key", "api_key_wo")
	if err != nil {
		return err
	}
	apiSecret, err := common.EffectiveSecretValue(d, "api_secret", "api_secret_wo")
	if err != nil {
		return err
	}
	mtlsCertDataBase64, err := common.EffectiveSecretValue(d, "mtls_cert_data_base64", "mtls_cert_data_base64_wo")
	if err != nil {
		return err
	}
	mtlsKeyDataBase64, err := common.EffectiveSecretValue(d, "mtls_key_data_base64", "mtls_key_data_base64_wo")
	if err != nil {
		return err
	}
	timeout := d.Get("timeout").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.UpdateGlobalSignAtlasTarget{
		Name:      name,
		ApiKey:    apiKey,
		ApiSecret: apiSecret,
		Token:     &token,
	}
	common.GetAkeylessPtr(&body.MtlsCertDataBase64, mtlsCertDataBase64)
	common.GetAkeylessPtr(&body.MtlsKeyDataBase64, mtlsKeyDataBase64)
	common.GetAkeylessPtr(&body.Timeout, timeout)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.UpdateGlobalSignAtlasTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceGlobalsignAtlasTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceGlobalsignAtlasTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceGlobalsignAtlasTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
