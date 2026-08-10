package akeyless

import (
	"context"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceAwsTarget() *schema.Resource {
	return &schema.Resource{
		Description: "AWS Target resource",
		Create:      resourceAwsTargetCreate,
		Read:        resourceAwsTargetRead,
		Update:      resourceAwsTargetUpdate,
		Delete:      resourceAwsTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAwsTargetImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("session_token"), cty.GetAttrPath("session_token_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("access_key"), cty.GetAttrPath("access_key_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"access_key_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "AWS access key ID",
			},
			"access_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS secret access key",
			},
			"access_key_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"access_key_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "access_key (write-only, not stored in state). Requires Terraform 1.11+. Bump access_key_wo_version to change it.",
			},
			"access_key_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"access_key_wo"},
				Description:  "Version trigger for access_key_wo. Increment to update the value.",
			},
			"session_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Required only for temporary security credentials retrieved using STS",
			},
			"session_token_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"session_token_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "session_token (write-only, not stored in state). Requires Terraform 1.11+. Bump session_token_wo_version to change it.",
			},
			"session_token_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"session_token_wo"},
				Description:  "Version trigger for session_token_wo. Increment to update the value.",
			},
			"region": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS region",
				Default:     "us-east-2",
			},
			"use_gw_cloud_identity": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Use the GW's Cloud IAM",
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
			"generate_external_id": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "A unique auto-generated value used in your AWS account when configuring your AWS IAM role to securely delegate access to Akeyless. Relevant only when using GW cloud ID",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"role_arn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS IAM role identifier that Gateway will assume in your AWS account, relevant only when using external ID",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceAwsTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	accessKeyId := d.Get("access_key_id").(string)
	accessKey, err := common.EffectiveSecretValue(d, "access_key", "access_key_wo")
	if err != nil {
		return err
	}
	sessionToken, err := common.EffectiveSecretValue(d, "session_token", "session_token_wo")
	if err != nil {
		return err
	}
	region := d.Get("region").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	generateExternalId := d.Get("generate_external_id").(bool)
	maxVersions := d.Get("max_versions").(string)
	roleArn := d.Get("role_arn").(string)

	body := akeyless_api.TargetCreateAws{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AccessKeyId, accessKeyId)
	common.GetAkeylessPtr(&body.AccessKey, accessKey)
	common.GetAkeylessPtr(&body.SessionToken, sessionToken)
	common.GetAkeylessPtr(&body.Region, region)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.GenerateExternalId, generateExternalId)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.RoleArn, roleArn)

	_, resp, err := client.TargetCreateAws(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceAwsTargetRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.Value == nil || rOut.Target == nil {
		return fmt.Errorf("can't get target details")
	}

	if rOut.Value.AwsTargetDetails.AwsAccessKeyId != nil {
		err = d.Set("access_key_id", *rOut.Value.AwsTargetDetails.AwsAccessKeyId)
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
	if rOut.Target.Comment != nil {
		err := d.Set("description", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}

	if rOut.Value.AwsTargetDetails.AwsSecretAccessKey != nil {
		err = common.SetSecretFromRead(d, "access_key", "access_key_wo", "access_key_wo_version", *rOut.Value.AwsTargetDetails.AwsSecretAccessKey)
		if err != nil {
			return err
		}
	}
	if rOut.Value.AwsTargetDetails.AwsSessionToken != nil {
		err = common.SetSecretFromRead(d, "session_token", "session_token_wo", "session_token_wo_version", *rOut.Value.AwsTargetDetails.AwsSessionToken)
		if err != nil {
			return err
		}
	}
	if rOut.Value.AwsTargetDetails.AwsRegion != nil {
		err = d.Set("region", *rOut.Value.AwsTargetDetails.AwsRegion)
		if err != nil {
			return err
		}
	}
	if rOut.Value.AwsTargetDetails.UseGwCloudIdentity != nil {
		err = d.Set("use_gw_cloud_identity", *rOut.Value.AwsTargetDetails.UseGwCloudIdentity)
		if err != nil {
			return err
		}
	}
	if rOut.Value.AwsTargetDetails.GwCloudIdentityExternalIdOpt != nil && rOut.Value.AwsTargetDetails.GwCloudIdentityExternalIdOpt.RoleArn != nil {
		err = d.Set("role_arn", *rOut.Value.AwsTargetDetails.GwCloudIdentityExternalIdOpt.RoleArn)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceAwsTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	accessKeyId := d.Get("access_key_id").(string)
	accessKey, err := common.SecretValueForUpdate(d, "access_key", "access_key_wo")
	if err != nil {
		return err
	}
	sessionToken, err := common.SecretValueForUpdate(d, "session_token", "session_token_wo")
	if err != nil {
		return err
	}
	region := d.Get("region").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	key := d.Get("key").(string)
	generateExternalId := d.Get("generate_external_id").(bool)
	maxVersions := d.Get("max_versions").(string)
	roleArn := d.Get("role_arn").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.TargetUpdateAws{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.AccessKeyId, accessKeyId)
	common.SetOptionalString(&body.AccessKey, accessKey)
	common.SetOptionalString(&body.SessionToken, sessionToken)
	common.GetAkeylessPtr(&body.Region, region)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.GenerateExternalId, generateExternalId)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.RoleArn, roleArn)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.TargetUpdateAws(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceAwsTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceAwsTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAwsTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
