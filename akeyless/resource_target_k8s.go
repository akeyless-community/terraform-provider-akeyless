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

func resourceK8sTarget() *schema.Resource {
	return &schema.Resource{
		Description: "K8S Target resource",
		Create:      resourceK8sTargetCreate,
		Read:        resourceK8sTargetRead,
		Update:      resourceK8sTargetUpdate,
		Delete:      resourceK8sTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceK8sTargetImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("k8s_cluster_token"), cty.GetAttrPath("k8s_cluster_token_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("k8s_cluster_ca_cert"), cty.GetAttrPath("k8s_cluster_ca_cert_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("k8s_client_certificate"), cty.GetAttrPath("k8s_client_certificate_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("k8s_client_key"), cty.GetAttrPath("k8s_client_key_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"k8s_cluster_endpoint": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "K8S cluster URL endpoint",
			},
			"k8s_cluster_ca_cert": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "K8S cluster CA certificate",
			},
			"k8s_cluster_ca_cert_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "K8S cluster CA certificate (write-only, not stored in state). Requires Terraform 1.11+. Bump k8s_cluster_ca_cert_wo_version to change it.",
			},
			"k8s_cluster_ca_cert_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for k8s_cluster_ca_cert_wo. Increment to update the certificate.",
			},
			"k8s_cluster_token": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "K8S cluster Bearer token",
			},
			"k8s_cluster_token_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "k8s_cluster_token (write-only, not stored in state). Requires Terraform 1.11+. Bump k8s_cluster_token_wo_version to change it.",
			},
			"k8s_cluster_token_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for k8s_cluster_token_wo. Increment to update the value.",
			},
			"k8s_auth_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "K8S auth type [token/certificate]",
			},
			"k8s_client_certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Content of the k8 client certificate (PEM format) in a Base64 format",
			},
			"k8s_client_certificate_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "Content of the k8 client certificate (PEM format) in a Base64 format (write-only, not stored in state). Requires Terraform 1.11+. Bump k8s_client_certificate_wo_version to change it.",
			},
			"k8s_client_certificate_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for k8s_client_certificate_wo. Increment to update the certificate.",
			},
			"k8s_client_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Content of the k8 client private key (PEM format) in a Base64 format",
			},
			"k8s_client_key_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "Content of the k8 client private key (PEM format) in a Base64 format (write-only, not stored in state). Requires Terraform 1.11+. Bump k8s_client_key_wo_version to change it.",
			},
			"k8s_client_key_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for k8s_client_key_wo. Increment to update the key.",
			},
			"k8s_cluster_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "K8S cluster name",
			},
			"use_gw_service_account": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Use the GW's service account",
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
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceK8sTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	k8sClusterEndpoint := d.Get("k8s_cluster_endpoint").(string)
	k8sClusterCaCert, err := common.EffectiveSecretValue(d, "k8s_cluster_ca_cert", "k8s_cluster_ca_cert_wo")
	if err != nil {
		return err
	}
	k8sClusterToken, err := common.EffectiveSecretValue(d, "k8s_cluster_token", "k8s_cluster_token_wo")
	if err != nil {
		return err
	}
	k8sAuthType := d.Get("k8s_auth_type").(string)
	k8sClientCertificate, err := common.EffectiveSecretValue(d, "k8s_client_certificate", "k8s_client_certificate_wo")
	if err != nil {
		return err
	}
	k8sClientKey, err := common.EffectiveSecretValue(d, "k8s_client_key", "k8s_client_key_wo")
	if err != nil {
		return err
	}
	k8sClusterName := d.Get("k8s_cluster_name").(string)
	useGwServiceAccount := d.Get("use_gw_service_account").(bool)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetCreateK8s{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.K8sClusterEndpoint, k8sClusterEndpoint)
	common.GetAkeylessPtr(&body.K8sClusterCaCert, k8sClusterCaCert)
	common.GetAkeylessPtr(&body.K8sClusterToken, k8sClusterToken)
	common.GetAkeylessPtr(&body.K8sAuthType, k8sAuthType)
	common.GetAkeylessPtr(&body.K8sClientCertificate, k8sClientCertificate)
	common.GetAkeylessPtr(&body.K8sClientKey, k8sClientKey)
	common.GetAkeylessPtr(&body.K8sClusterName, k8sClusterName)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	if d.HasChange("use_gw_service_account") {
		body.UseGwServiceAccount = &useGwServiceAccount
	}

	_, resp, err := client.TargetCreateK8s(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceK8sTargetRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.Value.NativeK8sTargetDetails.K8sClusterEndpoint != nil {
		err = d.Set("k8s_cluster_endpoint", *rOut.Value.NativeK8sTargetDetails.K8sClusterEndpoint)
		if err != nil {
			return err
		}
	}
	if rOut.Value.NativeK8sTargetDetails.K8sClusterCaCertificate != nil {
		err = common.SetSecretFromRead(d, "k8s_cluster_ca_cert", "k8s_cluster_ca_cert_wo", "k8s_cluster_ca_cert_wo_version", *rOut.Value.NativeK8sTargetDetails.K8sClusterCaCertificate)
		if err != nil {
			return err
		}
	}
	if rOut.Value.NativeK8sTargetDetails.K8sBearerToken != nil {
		err = common.SetSecretFromRead(d, "k8s_cluster_token", "k8s_cluster_token_wo", "k8s_cluster_token_wo_version", *rOut.Value.NativeK8sTargetDetails.K8sBearerToken)
		if err != nil {
			return err
		}
	}
	if rOut.Value.NativeK8sTargetDetails.K8sAuthType != nil {
		// Only set k8s_auth_type if it was explicitly configured by the user
		if _, ok := d.GetOk("k8s_auth_type"); ok {
			err = d.Set("k8s_auth_type", *rOut.Value.NativeK8sTargetDetails.K8sAuthType)
			if err != nil {
				return err
			}
		}
	}
	if rOut.Value.NativeK8sTargetDetails.K8sClientCertData != nil {
		err = common.SetSecretFromRead(d, "k8s_client_certificate", "k8s_client_certificate_wo", "k8s_client_certificate_wo_version", *rOut.Value.NativeK8sTargetDetails.K8sClientCertData)
		if err != nil {
			return err
		}
	}
	if rOut.Value.NativeK8sTargetDetails.K8sClientKeyData != nil {
		err = common.SetSecretFromRead(d, "k8s_client_key", "k8s_client_key_wo", "k8s_client_key_wo_version", *rOut.Value.NativeK8sTargetDetails.K8sClientKeyData)
		if err != nil {
			return err
		}
	}
	if rOut.Value.NativeK8sTargetDetails.K8sClusterName != nil {
		err = d.Set("k8s_cluster_name", *rOut.Value.NativeK8sTargetDetails.K8sClusterName)
		if err != nil {
			return err
		}
	}
	if rOut.Value.NativeK8sTargetDetails.UseGwServiceAccount != nil {
		err = d.Set("use_gw_service_account", *rOut.Value.NativeK8sTargetDetails.UseGwServiceAccount)
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

func resourceK8sTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	k8sClusterEndpoint := d.Get("k8s_cluster_endpoint").(string)
	k8sClusterCaCert, err := common.EffectiveSecretValue(d, "k8s_cluster_ca_cert", "k8s_cluster_ca_cert_wo")
	if err != nil {
		return err
	}
	k8sClusterToken, err := common.EffectiveSecretValue(d, "k8s_cluster_token", "k8s_cluster_token_wo")
	if err != nil {
		return err
	}
	k8sAuthType := d.Get("k8s_auth_type").(string)
	k8sClientCertificate, err := common.EffectiveSecretValue(d, "k8s_client_certificate", "k8s_client_certificate_wo")
	if err != nil {
		return err
	}
	k8sClientKey, err := common.EffectiveSecretValue(d, "k8s_client_key", "k8s_client_key_wo")
	if err != nil {
		return err
	}
	k8sClusterName := d.Get("k8s_cluster_name").(string)
	useGwServiceAccount := d.Get("use_gw_service_account").(bool)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	description := d.Get("description").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.TargetUpdateK8s{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.K8sClusterEndpoint, k8sClusterEndpoint)
	common.GetAkeylessPtr(&body.K8sClusterCaCert, k8sClusterCaCert)
	common.GetAkeylessPtr(&body.K8sClusterToken, k8sClusterToken)
	common.GetAkeylessPtr(&body.K8sAuthType, k8sAuthType)
	common.GetAkeylessPtr(&body.K8sClientCertificate, k8sClientCertificate)
	common.GetAkeylessPtr(&body.K8sClientKey, k8sClientKey)
	common.GetAkeylessPtr(&body.K8sClusterName, k8sClusterName)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)
	if d.HasChange("use_gw_service_account") {
		body.UseGwServiceAccount = &useGwServiceAccount
	}

	_, resp, err := client.TargetUpdateK8s(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceK8sTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceK8sTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceK8sTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
