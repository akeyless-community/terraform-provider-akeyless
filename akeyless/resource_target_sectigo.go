package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceSectigoTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Sectigo Target resource",
		Create:      resourceSectigoTargetCreate,
		Read:        resourceSectigoTargetRead,
		Update:      resourceSectigoTargetUpdate,
		Delete:      resourceSectigoTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceSectigoTargetImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("password"), cty.GetAttrPath("password_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"certificate_profile_id": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "Certificate Profile ID in Sectigo account",
			},
			"customer_uri": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Customer URI in Sectigo account",
			},
			"external_requester": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "External Requester - a comma separated list of emails",
			},
			"organization_id": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "Organization ID in Sectigo account",
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Password for Sectigo account",
			},
			"password_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "password (write-only, not stored in state). Requires Terraform 1.11+. Bump password_wo_version to change it.",
			},
			"password_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for password_wo. Increment to update the value.",
			},
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Username for Sectigo account",
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
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used.",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults",
			},
			"timeout": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Timeout waiting for certificate validation in Duration format (1h - 1 Hour, 20m - 20 Minutes, 33m3s - 33 Minutes and 3 Seconds), maximum 1h.",
				Default:          "5m",
				DiffSuppressFunc: common.DiffSuppressDuration,
			},
		},
	}
}

func resourceSectigoTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	certificateProfileId := d.Get("certificate_profile_id").(int)
	customerUri := d.Get("customer_uri").(string)
	externalRequester := d.Get("external_requester").(string)
	organizationId := d.Get("organization_id").(int)
	password, err := common.EffectiveSecretValue(d, "password", "password_wo")
	if err != nil {
		return err
	}
	username := d.Get("username").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	timeout := d.Get("timeout").(string)

	body := akeyless_api.TargetCreateSectigo{
		Name:                 name,
		CertificateProfileId: int64(certificateProfileId),
		CustomerUri:          customerUri,
		ExternalRequester:    externalRequester,
		OrganizationId:       int64(organizationId),
		Password:             password,
		Username:             username,
		Token:                &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.Timeout, timeout)

	_, resp, err := client.TargetCreateSectigo(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceSectigoTargetRead(d *schema.ResourceData, m interface{}) error {
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
		return common.HandleReadError(d, "can't get target details", res, err)
	}

	if rOut.Value != nil && rOut.Value.SectigoTargetDetails != nil {
		if rOut.Value.SectigoTargetDetails.CertificateProfileId != nil {
			err = d.Set("certificate_profile_id", int(*rOut.Value.SectigoTargetDetails.CertificateProfileId))
			if err != nil {
				return err
			}
		}
		if rOut.Value.SectigoTargetDetails.CustomerUri != nil {
			err = d.Set("customer_uri", *rOut.Value.SectigoTargetDetails.CustomerUri)
			if err != nil {
				return err
			}
		}
		if rOut.Value.SectigoTargetDetails.ExternalRequester != nil {
			err = d.Set("external_requester", *rOut.Value.SectigoTargetDetails.ExternalRequester)
			if err != nil {
				return err
			}
		}
		if rOut.Value.SectigoTargetDetails.OrgId != nil {
			err = d.Set("organization_id", int(*rOut.Value.SectigoTargetDetails.OrgId))
			if err != nil {
				return err
			}
		}
		if rOut.Value.SectigoTargetDetails.Password != nil {
			err = common.SetSecretFromRead(d, "password", "password_wo", "password_wo_version", *rOut.Value.SectigoTargetDetails.Password)
			if err != nil {
				return err
			}
		}
		if rOut.Value.SectigoTargetDetails.Username != nil {
			err = d.Set("username", *rOut.Value.SectigoTargetDetails.Username)
			if err != nil {
				return err
			}
		}
		if rOut.Value.SectigoTargetDetails.Timeout != nil {
			// API returns nanoseconds as int64, convert to duration string
			timeout := *rOut.Value.SectigoTargetDetails.Timeout
			duration := common.ConvertNanoSecondsIntoDurationString(timeout)
			err = d.Set("timeout", duration)
			if err != nil {
				return err
			}
		}
	}
	if rOut.Target != nil && rOut.Target.Comment != nil {
		err := d.Set("description", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}
	if rOut.Target != nil && rOut.Target.ProtectionKeyName != nil {
		err = d.Set("key", *rOut.Target.ProtectionKeyName)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceSectigoTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	certificateProfileId := d.Get("certificate_profile_id").(int)
	customerUri := d.Get("customer_uri").(string)
	externalRequester := d.Get("external_requester").(string)
	organizationId := d.Get("organization_id").(int)
	password, err := common.EffectiveSecretValue(d, "password", "password_wo")
	if err != nil {
		return err
	}
	username := d.Get("username").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)
	maxVersions := d.Get("max_versions").(string)
	timeout := d.Get("timeout").(string)

	body := akeyless_api.TargetUpdateSectigo{
		Name:                 name,
		CertificateProfileId: int64(certificateProfileId),
		CustomerUri:          customerUri,
		ExternalRequester:    externalRequester,
		OrganizationId:       int64(organizationId),
		Password:             password,
		Username:             username,
		Token:                &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.Timeout, timeout)

	_, resp, err := client.TargetUpdateSectigo(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceSectigoTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceSectigoTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceSectigoTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
