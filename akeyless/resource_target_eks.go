package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceEksTarget() *schema.Resource {
	return &schema.Resource{
		Description: "EKS Target resource",
		Create:      resourceEksTargetCreate,
		Read:        resourceEksTargetRead,
		Update:      resourceEksTargetUpdate,
		Delete:      resourceEksTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceEksTargetImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("eks_cluster_ca_cert"), cty.GetAttrPath("eks_cluster_ca_cert_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("eks_secret_access_key"), cty.GetAttrPath("eks_secret_access_key_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"eks_cluster_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "EKS cluster name",
			},
			"eks_cluster_endpoint": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "EKS cluster URL endpoint",
			},
			"eks_cluster_ca_cert": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "EKS cluster CA certificate",
			},
			"eks_cluster_ca_cert_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"eks_cluster_ca_cert_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "EKS cluster CA certificate (write-only, not stored in state). Requires Terraform 1.11+. Bump eks_cluster_ca_cert_wo_version to change it.",
			},
			"eks_cluster_ca_cert_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"eks_cluster_ca_cert_wo"},
				Description:  "Version trigger for eks_cluster_ca_cert_wo. Increment to update the value.",
			},
			"eks_access_key_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Access Key ID",
			},
			"eks_secret_access_key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Secret Access Key",
			},
			"eks_secret_access_key_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"eks_secret_access_key_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "Secret Access Key (write-only, not stored in state). Requires Terraform 1.11+. Bump eks_secret_access_key_wo_version to change it.",
			},
			"eks_secret_access_key_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"eks_secret_access_key_wo"},
				Description:  "Version trigger for eks_secret_access_key_wo. Increment to update the value.",
			},
			"use_gw_cloud_identity": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Use the GW's Cloud IAM",
			},
			"eks_region": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Region",
				Default:     "us-east-2",
			},
			"key": {
				Type:        schema.TypeString,
				Required:    false,
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
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceEksTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	eksClusterName := d.Get("eks_cluster_name").(string)
	eksClusterEndpoint := d.Get("eks_cluster_endpoint").(string)
	eksClusterCaCert, err := common.EffectiveSecretValue(d, "eks_cluster_ca_cert", "eks_cluster_ca_cert_wo")
	if err != nil {
		return err
	}
	eksAccessKeyId := d.Get("eks_access_key_id").(string)
	eksSecretAccessKey, err := common.EffectiveSecretValue(d, "eks_secret_access_key", "eks_secret_access_key_wo")
	if err != nil {
		return err
	}
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	eksRegion := d.Get("eks_region").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.TargetCreateEks{
		Name:               name,
		EksClusterName:     eksClusterName,
		EksClusterEndpoint: eksClusterEndpoint,
		EksClusterCaCert:   eksClusterCaCert,
		EksAccessKeyId:     eksAccessKeyId,
		EksSecretAccessKey: eksSecretAccessKey,
		Token:              &token,
	}
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.EksRegion, eksRegion)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.TargetCreateEks(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceEksTargetRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.Value.EksTargetDetails.EksClusterName != nil {
		err = d.Set("eks_cluster_name", *rOut.Value.EksTargetDetails.EksClusterName)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksTargetDetails.EksClusterEndpoint != nil {
		err = d.Set("eks_cluster_endpoint", *rOut.Value.EksTargetDetails.EksClusterEndpoint)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksTargetDetails.EksClusterCaCertificate != nil {
		err = common.SetSecretFromRead(d, "eks_cluster_ca_cert", "eks_cluster_ca_cert_wo", "eks_cluster_ca_cert_wo_version", *rOut.Value.EksTargetDetails.EksClusterCaCertificate)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksTargetDetails.EksAccessKeyId != nil {
		err = d.Set("eks_access_key_id", *rOut.Value.EksTargetDetails.EksAccessKeyId)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksTargetDetails.EksSecretAccessKey != nil {
		err = common.SetSecretFromRead(d, "eks_secret_access_key", "eks_secret_access_key_wo", "eks_secret_access_key_wo_version", *rOut.Value.EksTargetDetails.EksSecretAccessKey)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksTargetDetails.UseGwCloudIdentity != nil {
		err = d.Set("use_gw_cloud_identity", *rOut.Value.EksTargetDetails.UseGwCloudIdentity)
		if err != nil {
			return err
		}
	}
	if rOut.Value.EksTargetDetails.EksRegion != nil {
		err = d.Set("eks_region", *rOut.Value.EksTargetDetails.EksRegion)
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

	d.SetId(path)

	return nil
}

func resourceEksTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	eksClusterName := d.Get("eks_cluster_name").(string)
	eksClusterEndpoint := d.Get("eks_cluster_endpoint").(string)
	eksClusterCaCert, err := common.RequiredSecretValueForUpdate(d, "eks_cluster_ca_cert", "eks_cluster_ca_cert_wo")
	if err != nil {
		return err
	}
	eksAccessKeyId := d.Get("eks_access_key_id").(string)
	eksSecretAccessKey, err := common.RequiredSecretValueForUpdate(d, "eks_secret_access_key", "eks_secret_access_key_wo")
	if err != nil {
		return err
	}
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	eksRegion := d.Get("eks_region").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.TargetUpdateEks{
		Name:               name,
		EksClusterName:     eksClusterName,
		EksClusterEndpoint: eksClusterEndpoint,
		EksClusterCaCert:   eksClusterCaCert,
		EksAccessKeyId:     eksAccessKeyId,
		EksSecretAccessKey: eksSecretAccessKey,
		Token:              &token,
	}
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.EksRegion, eksRegion)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.TargetUpdateEks(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceEksTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceEksTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceEksTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
