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

func resourceZerosslTarget() *schema.Resource {
	return &schema.Resource{
		Description: "ZeroSSL Target resource",
		Create:      resourceZerosslTargetCreate,
		Read:        resourceZerosslTargetRead,
		Update:      resourceZerosslTargetUpdate,
		Delete:      resourceZerosslTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceZerosslTargetImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("imap_password"), cty.GetAttrPath("imap_password_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("api_key"), cty.GetAttrPath("api_key_wo")),
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
				Sensitive:   true,
				Description: "API Key of the ZeroSSLTarget account",
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
			"imap_username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Username to access the IMAP service",
			},
			"imap_password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Password to access the IMAP service",
			},
			"imap_password_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "imap_password (write-only, not stored in state). Requires Terraform 1.11+. Bump imap_password_wo_version to change it.",
			},
			"imap_password_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for imap_password_wo. Increment to update the value.",
			},
			"imap_fqdn": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "FQDN or IPv4 address of the IMAP service. Must be FQDN if the IMAP is using TLS",
			},
			"imap_target_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Validation email to use when asking ZeroSSL to send a validation email, if empty will use imap-username",
			},
			"imap_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Port of the IMAP service",
				Default:     "993",
			},
			"timeout": {
				Type:             schema.TypeString,
				Optional:         true,
				DiffSuppressFunc: common.DiffSuppressDuration,
				Description:      "Timeout waiting for certificate validation in Duration format (1h - 1 Hour, 20m - 20 Minutes, 33m3s - 33 Minutes and 3 Seconds), maximum 1h",
				Default:          "5m",
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

func resourceZerosslTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	apiKey, err := common.EffectiveSecretValue(d, "api_key", "api_key_wo")
	if err != nil {
		return err
	}
	imapUsername := d.Get("imap_username").(string)
	imapPassword, err := common.EffectiveSecretValue(d, "imap_password", "imap_password_wo")
	if err != nil {
		return err
	}
	imapFqdn := d.Get("imap_fqdn").(string)
	imapTargetEmail := d.Get("imap_target_email").(string)
	imapPort := d.Get("imap_port").(string)
	timeout := d.Get("timeout").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.TargetCreateZeroSSL{
		Name:         name,
		ApiKey:       apiKey,
		ImapUsername: imapUsername,
		ImapPassword: imapPassword,
		ImapFqdn:     imapFqdn,
		Token:        &token,
	}
	common.GetAkeylessPtr(&body.Timeout, timeout)
	common.GetAkeylessPtr(&body.ImapTargetEmail, imapTargetEmail)
	common.GetAkeylessPtr(&body.ImapPort, imapPort)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.TargetCreateZeroSSL(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceZerosslTargetRead(d *schema.ResourceData, m interface{}) error {
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

		if targetDetails.ZerosslTargetDetails.ApiKey != nil {
			err := common.SetSecretFromRead(d, "api_key", "api_key_wo", "api_key_wo_version", *targetDetails.ZerosslTargetDetails.ApiKey)
			if err != nil {
				return err
			}
		}
		if targetDetails.ZerosslTargetDetails.Timeout != nil {
			timeout := *targetDetails.ZerosslTargetDetails.Timeout
			duration := common.ConvertNanoSecondsIntoDurationString(timeout)

			err := d.Set("timeout", duration)
			if err != nil {
				return err
			}
		}
		if targetDetails.ZerosslTargetDetails.ImapUser != nil {
			err := d.Set("imap_username", *targetDetails.ZerosslTargetDetails.ImapUser)
			if err != nil {
				return err
			}
		}
		if targetDetails.ZerosslTargetDetails.ImapPassword != nil {
			err := common.SetSecretFromRead(d, "imap_password", "imap_password_wo", "imap_password_wo_version", *targetDetails.ZerosslTargetDetails.ImapPassword)
			if err != nil {
				return err
			}
		}
		if targetDetails.ZerosslTargetDetails.ImapFqdn != nil {
			err := d.Set("imap_fqdn", *targetDetails.ZerosslTargetDetails.ImapFqdn)
			if err != nil {
				return err
			}
		}
		if targetDetails.ZerosslTargetDetails.ValidationEmail != nil {
			err := d.Set("imap_target_email", *targetDetails.ZerosslTargetDetails.ValidationEmail)
			if err != nil {
				return err
			}
		}
		if targetDetails.ZerosslTargetDetails.ImapPort != nil {
			err := d.Set("imap_port", *targetDetails.ZerosslTargetDetails.ImapPort)
			if err != nil {
				return err
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

func resourceZerosslTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	apiKey, err := common.EffectiveSecretValue(d, "api_key", "api_key_wo")
	if err != nil {
		return err
	}
	imapUsername := d.Get("imap_username").(string)
	imapPassword, err := common.EffectiveSecretValue(d, "imap_password", "imap_password_wo")
	if err != nil {
		return err
	}
	imapFqdn := d.Get("imap_fqdn").(string)
	imapTargetEmail := d.Get("imap_target_email").(string)
	imapPort := d.Get("imap_port").(string)
	timeout := d.Get("timeout").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.TargetUpdateZeroSSL{
		Name:         name,
		ApiKey:       apiKey,
		ImapUsername: imapUsername,
		ImapPassword: imapPassword,
		ImapFqdn:     imapFqdn,
		Token:        &token,
	}
	common.GetAkeylessPtr(&body.Timeout, timeout)
	common.GetAkeylessPtr(&body.ImapTargetEmail, imapTargetEmail)
	common.GetAkeylessPtr(&body.ImapPort, imapPort)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.TargetUpdateZeroSSL(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceZerosslTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceZerosslTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceZerosslTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
