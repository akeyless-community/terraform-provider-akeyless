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

func resourceSplunkTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Splunk Target resource",
		Create:      resourceSplunkTargetCreate,
		Read:        resourceSplunkTargetRead,
		Update:      resourceSplunkTargetUpdate,
		Delete:      resourceSplunkTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceSplunkTargetImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("splunk_token"), cty.GetAttrPath("splunk_token_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("password"), cty.GetAttrPath("password_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Splunk server URL",
			},
			"username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Splunk Username (used when authenticating with username/password)",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Splunk Password (used when authenticating with username/password)",
			},
			"password_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"password_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "password (write-only, not stored in state). Requires Terraform 1.11+. Bump password_wo_version to change it.",
			},
			"password_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"password_wo"},
				Description:  "Version trigger for password_wo. Increment to update the value.",
			},
			"splunk_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Splunk Token (used when authenticating with token)",
			},
			"splunk_token_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"splunk_token_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "splunk_token (write-only, not stored in state). Requires Terraform 1.11+. Bump splunk_token_wo_version to change it.",
			},
			"splunk_token_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"splunk_token_wo"},
				Description:  "Version trigger for splunk_token_wo. Increment to update the value.",
			},
			"token_owner": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Splunk Token Owner (required when using token authentication for rotation)",
			},
			"audience": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Splunk token audience (required when using token authentication for rotation)",
			},
			"use_tls": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Use TLS certificate verification when connecting to the Splunk management API",

				Default: false,
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
		},
	}
}

func resourceSplunkTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	url := d.Get("url").(string)
	username := d.Get("username").(string)
	password, err := common.EffectiveSecretValue(d, "password", "password_wo")
	if err != nil {
		return err
	}
	splunkToken, err := common.EffectiveSecretValue(d, "splunk_token", "splunk_token_wo")
	if err != nil {
		return err
	}
	tokenOwner := d.Get("token_owner").(string)
	audience := d.Get("audience").(string)
	useTls := d.Get("use_tls").(bool)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.TargetCreateSplunk{
		Name:  name,
		Url:   url,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Username, username)
	common.GetAkeylessPtr(&body.Password, password)
	common.GetAkeylessPtr(&body.SplunkToken, splunkToken)
	common.GetAkeylessPtr(&body.TokenOwner, tokenOwner)
	common.GetAkeylessPtr(&body.Audience, audience)
	common.GetAkeylessPtr(&body.UseTls, useTls)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.TargetCreateSplunk(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceSplunkTargetRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.Value != nil && rOut.Value.SplunkTargetDetails != nil {
		details := rOut.Value.SplunkTargetDetails
		if details.SplunkUrl != nil {
			err = d.Set("url", *details.SplunkUrl)
			if err != nil {
				return err
			}
		}
		if details.Username != nil {
			err = d.Set("username", *details.Username)
			if err != nil {
				return err
			}
		}
		if details.Password != nil {
			err = common.SetSecretFromRead(d, "password", "password_wo", "password_wo_version", *details.Password)
			if err != nil {
				return err
			}
		}
		if details.Token != nil {
			err = common.SetSecretFromRead(d, "splunk_token", "splunk_token_wo", "splunk_token_wo_version", *details.Token)
			if err != nil {
				return err
			}
		}
		if details.TokenOwner != nil {
			err = d.Set("token_owner", *details.TokenOwner)
			if err != nil {
				return err
			}
		}
		if details.Audience != nil {
			err = d.Set("audience", *details.Audience)
			if err != nil {
				return err
			}
		}
		if details.UseTls != nil {
			err = d.Set("use_tls", *details.UseTls)
			if err != nil {
				return err
			}
		}
	}

	if rOut.Target != nil {
		if rOut.Target.Comment != nil {
			err = d.Set("description", *rOut.Target.Comment)
			if err != nil {
				return err
			}
		}
		if rOut.Target.ProtectionKeyName != nil {
			err = d.Set("key", *rOut.Target.ProtectionKeyName)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceSplunkTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	// TODO: use TargetUpdateSplunk instead of UpdateTarget when the API is ready
	body := akeyless_api.UpdateTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.NewName, name)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.UpdateTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceSplunkTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceSplunkTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceSplunkTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
