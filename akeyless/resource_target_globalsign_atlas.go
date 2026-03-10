package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
			"api_secret": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "API Secret of the GlobalSign Atlas account",
			},
			"mtls_cert_data_base64": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Mutual TLS Certificate contents of the GlobalSign Atlas account encoded in base64",
			},
			"mtls_key_data_base64": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Mutual TLS Key contents of the GlobalSign Atlas account encoded in base64",
			},
			"timeout": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Timeout waiting for certificate validation in Duration format (1h - 1 Hour, 20m - 20 Minutes, 33m3s - 33 Minutes and 3 Seconds), maximum 1h",
				Default:     "5m",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					// Normalize duration strings to compare them
					oldDur, oldErr := time.ParseDuration(old)
					newDur, newErr := time.ParseDuration(new)
					if oldErr != nil || newErr != nil {
						return false
					}
					return oldDur == newDur
				},
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
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
	apiKey := d.Get("api_key").(string)
	apiSecret := d.Get("api_secret").(string)
	mtlsCertDataBase64 := d.Get("mtls_cert_data_base64").(string)
	mtlsKeyDataBase64 := d.Get("mtls_key_data_base64").(string)
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

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("failed to get target details: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to get target details: %w", err)
	}

	if rOut.Value != nil {
		targetDetails := *rOut.Value

		if targetDetails.GlobalsignAtlasTargetDetails != nil {
			if targetDetails.GlobalsignAtlasTargetDetails.ApiKey != nil {
				err := d.Set("api_key", *targetDetails.GlobalsignAtlasTargetDetails.ApiKey)
				if err != nil {
					return err
				}
			}
			if targetDetails.GlobalsignAtlasTargetDetails.ApiSecret != nil {
				err := d.Set("api_secret", *targetDetails.GlobalsignAtlasTargetDetails.ApiSecret)
				if err != nil {
					return err
				}
			}
			if targetDetails.GlobalsignAtlasTargetDetails.MtlsCert != nil {
				err := d.Set("mtls_cert_data_base64", *targetDetails.GlobalsignAtlasTargetDetails.MtlsCert)
				if err != nil {
					return err
				}
			}
			if targetDetails.GlobalsignAtlasTargetDetails.MtlsKey != nil {
				err := d.Set("mtls_key_data_base64", *targetDetails.GlobalsignAtlasTargetDetails.MtlsKey)
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
	apiKey := d.Get("api_key").(string)
	apiSecret := d.Get("api_secret").(string)
	mtlsCertDataBase64 := d.Get("mtls_cert_data_base64").(string)
	mtlsKeyDataBase64 := d.Get("mtls_key_data_base64").(string)
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
