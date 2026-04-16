// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePolicyKeys() *schema.Resource {
	return &schema.Resource{
		Description: "Policy Keys Resource",
		Create:      resourcePolicyKeysCreate,
		Read:        resourcePolicyKeysRead,
		Update:      resourcePolicyKeysUpdate,
		Delete:      resourcePolicyKeysDelete,
		Importer: &schema.ResourceImporter{
			State: resourcePolicyKeysImport,
		},
		Schema: map[string]*schema.Schema{
			"path": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "The path the policy refers to",
				DiffSuppressFunc: common.DiffSuppressOnSlashes,
			},
			"allowed_algorithms": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specify allowed key algorithms (e.g., [RSA2048,AES128GCM])",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"allowed_key_names": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specify allowed protection key names",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"allowed_key_types": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specify allowed key protection types (dfc, classic-key)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"max_rotation_interval_days": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Set the maximum rotation interval for automatic key rotation",
			},
			"object_types": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "The object types this policy will apply to (items, targets)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourcePolicyKeysCreate(d *schema.ResourceData, m any) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Get("path").(string)
	allowedAlgorithms := d.Get("allowed_algorithms").([]any)
	allowedKeyNames := d.Get("allowed_key_names").([]any)
	allowedKeyTypes := d.Get("allowed_key_types").([]any)
	maxRotation := d.Get("max_rotation_interval_days").(int)
	objectTypes := d.Get("object_types").([]any)

	body := akeyless_api.PolicyCreateKeys{
		Path:  path,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AllowedAlgorithms, common.ExpandStringList(allowedAlgorithms))
	common.GetAkeylessPtr(&body.AllowedKeyNames, common.ExpandStringList(allowedKeyNames))
	common.GetAkeylessPtr(&body.AllowedKeyTypes, common.ExpandStringList(allowedKeyTypes))
	common.GetAkeylessPtr(&body.MaxRotationIntervalDays, maxRotation)
	common.GetAkeylessPtr(&body.ObjectTypes, common.ExpandStringList(objectTypes))

	rOut, resp, err := client.PolicyCreateKeys(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create policy keys", resp, err)
	}

	if rOut.Id != nil {
		d.SetId(*rOut.Id)
	}

	return nil
}

func resourcePolicyKeysRead(d *schema.ResourceData, m any) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	body := akeyless_api.PoliciesGet{
		Id:    d.Id(),
		Token: &token,
	}

	rOut, res, err := client.PoliciesGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get policy keys", res, err)
	}

	if rOut.Policy == nil {
		d.SetId("")
		return nil
	}

	policy := rOut.Policy

	if policy.Path != nil {
		if err := d.Set("path", *policy.Path); err != nil {
			return err
		}
	}
	if policy.AllowedAlgorithms != nil {
		if err := d.Set("allowed_algorithms", policy.AllowedAlgorithms); err != nil {
			return err
		}
	}
	if policy.AllowedKeyNames != nil {
		if err := d.Set("allowed_key_names", policy.AllowedKeyNames); err != nil {
			return err
		}
	}
	if policy.AllowedKeyTypes != nil {
		if err := d.Set("allowed_key_types", policy.AllowedKeyTypes); err != nil {
			return err
		}
	}
	if policy.MaxRotationIntervalDays != nil {
		if err := d.Set("max_rotation_interval_days", int(*policy.MaxRotationIntervalDays)); err != nil {
			return err
		}
	}
	if policy.ObjectTypes != nil {
		if err := d.Set("object_types", policy.ObjectTypes); err != nil {
			return err
		}
	}

	return nil
}

func resourcePolicyKeysUpdate(d *schema.ResourceData, m any) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Get("path").(string)
	allowedAlgorithms := d.Get("allowed_algorithms").([]any)
	allowedKeyNames := d.Get("allowed_key_names").([]any)
	allowedKeyTypes := d.Get("allowed_key_types").([]any)
	maxRotation := d.Get("max_rotation_interval_days").(int)
	objectTypes := d.Get("object_types").([]any)

	body := akeyless_api.PolicyUpdateKeys{
		Id:    d.Id(),
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Path, path)
	common.GetAkeylessPtr(&body.AllowedAlgorithms, common.ExpandStringList(allowedAlgorithms))
	common.GetAkeylessPtr(&body.AllowedKeyNames, common.ExpandStringList(allowedKeyNames))
	common.GetAkeylessPtr(&body.AllowedKeyTypes, common.ExpandStringList(allowedKeyTypes))
	common.GetAkeylessPtr(&body.MaxRotationIntervalDays, maxRotation)
	common.GetAkeylessPtr(&body.ObjectTypes, common.ExpandStringList(objectTypes))

	_, resp, err := client.PolicyUpdateKeys(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update policy keys", resp, err)
	}

	return nil
}

func resourcePolicyKeysDelete(d *schema.ResourceData, m any) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	body := akeyless_api.PoliciesDelete{
		Id:    d.Id(),
		Token: &token,
	}

	_, resp, err := client.PoliciesDelete(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't delete policy keys", resp, err)
	}

	return nil
}

func resourcePolicyKeysImport(d *schema.ResourceData, m any) ([]*schema.ResourceData, error) {
	err := resourcePolicyKeysRead(d, m)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
