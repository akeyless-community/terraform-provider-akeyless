// generated
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceDynamicSecretEks() *schema.Resource {
	return &schema.Resource{
		Description: "Amazon Elastic Kubernetes Service (Amazon EKS) dynamic secret",
		Create:      resourceDynamicSecretEksCreate,
		Read:        resourceDynamicSecretEksRead,
		Update:      resourceDynamicSecretEksUpdate,
		Delete:      resourceDynamicSecretEksDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretEksImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("eks_cluster_ca_cert"), cty.GetAttrPath("eks_cluster_ca_cert_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("eks_secret_access_key"), cty.GetAttrPath("eks_secret_access_key_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of existing target to use in dynamic secret creation",
			},
			"eks_cluster_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "EKS cluster name. Must match the EKS cluster name you want to connect to.",
			},
			"eks_cluster_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "EKS Cluster endpoint. https:// , <DNS / IP> of the cluster.",
			},
			"eks_cluster_ca_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "EKS Cluster certificate. Base 64 encoded certificate.",
			},
			"eks_cluster_ca_cert_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "EKS Cluster certificate. Base 64 encoded certificate. (write-only, not stored in state). Requires Terraform 1.11+. Bump eks_cluster_ca_cert_wo_version to change it.",
			},
			"eks_cluster_ca_cert_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for eks_cluster_ca_cert_wo. Increment to update the password.",
			},
			"eks_access_key_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "EKS Access Key ID",
			},
			"eks_secret_access_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "EKS Secret Access Key",
			},
			"eks_secret_access_key_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "EKS Secret Access Key (write-only, not stored in state). Requires Terraform 1.11+. Bump eks_secret_access_key_wo_version to change it.",
			},
			"eks_secret_access_key_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for eks_secret_access_key_wo. Increment to update the password.",
			},
			"eks_region": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "EKS Region",
				Default:     "us-east-2",
			},
			"eks_assume_role": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Role ARN. Role to assume when connecting to the EKS cluster",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Encrypt dynamic secret details with following key",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_cluster_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The K8s cluster endpoint URL",
			},
			"secure_access_allow_port_forwading": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable Port forwarding while using CLI access.",
			},
			"secure_access_certificate_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Secure Access",
			},
			"secure_access_bastion_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Bastion",
				Deprecated:  "use secure_access_certificate_issuer instead",
			},
			"secure_access_delay": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The delay duration, in seconds, to wait after generating just-in-time credentials. Accepted range: 0-120 seconds",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable Web Secure Remote Access",
			},
		},
	}
}

func resourceDynamicSecretEksCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
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
	eksRegion := d.Get("eks_region").(string)
	eksAssumeRole := d.Get("eks_assume_role").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessClusterEndpoint := d.Get("secure_access_cluster_endpoint").(string)
	secureAccessAllowPortForwading := d.Get("secure_access_allow_port_forwading").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	if secureAccessCertificateIssuer == "" {
		secureAccessCertificateIssuer = d.Get("secure_access_bastion_issuer").(string)
	}
	secureAccessDelay := d.Get("secure_access_delay").(int)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.DynamicSecretCreateEks{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.EksClusterName, eksClusterName)
	common.GetAkeylessPtr(&body.EksClusterEndpoint, eksClusterEndpoint)
	common.GetAkeylessPtr(&body.EksClusterCaCert, eksClusterCaCert)
	common.GetAkeylessPtr(&body.EksAccessKeyId, eksAccessKeyId)
	common.GetAkeylessPtr(&body.EksSecretAccessKey, eksSecretAccessKey)
	common.GetAkeylessPtr(&body.EksRegion, eksRegion)
	common.GetAkeylessPtr(&body.EksAssumeRole, eksAssumeRole)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ItemCustomFields, itemCustomFields)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessClusterEndpoint, secureAccessClusterEndpoint)
	common.GetAkeylessPtr(&body.SecureAccessAllowPortForwading, secureAccessAllowPortForwading)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessDelay, int64(secureAccessDelay))
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, resp, err := client.DynamicSecretCreateEks(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretEksRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get dynamic secret value", res, err)
	}
	if rOut.EksClusterName != nil {
		err = d.Set("eks_cluster_name", *rOut.EksClusterName)
		if err != nil {
			return err
		}
	}
	if rOut.EksClusterEndpoint != nil {
		err = d.Set("eks_cluster_endpoint", *rOut.EksClusterEndpoint)
		if err != nil {
			return err
		}
	}
	if rOut.EksAccessKeyId != nil {
		err = d.Set("eks_access_key_id", *rOut.EksAccessKeyId)
		if err != nil {
			return err
		}
	}
	if rOut.EksSecretAccessKey != nil {
		err = common.SetSecretFromRead(d, "eks_secret_access_key", "eks_secret_access_key_wo", "eks_secret_access_key_wo_version", *rOut.EksSecretAccessKey)
		if err != nil {
			return err
		}
	}
	if rOut.EksRegion != nil {
		err = d.Set("eks_region", *rOut.EksRegion)
		if err != nil {
			return err
		}
	}
	if rOut.EksAssumeRole != nil {
		err = d.Set("eks_assume_role", *rOut.EksAssumeRole)
		if err != nil {
			return err
		}
	}
	if rOut.UserTtl != nil {
		err = d.Set("user_ttl", *rOut.UserTtl)
		if err != nil {
			return err
		}
	}
	if rOut.Tags != nil {
		err = d.Set("tags", rOut.Tags)
		if err != nil {
			return err
		}
	}

	if rOut.DynamicSecretKey != nil {
		err = common.SetDataByPrefixSlash(d, "encryption_key_name", *rOut.DynamicSecretKey, d.Get("encryption_key_name").(string))
		if err != nil {
			return err
		}
	}

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = common.SetDataByPrefixSlash(d, "target_name", targetName, d.Get("target_name").(string))
		if err != nil {
			return err
		}
	}

	if rOut.EksClusterCaCertificate != nil {
		err = common.SetSecretFromRead(d, "eks_cluster_ca_cert", "eks_cluster_ca_cert_wo", "eks_cluster_ca_cert_wo_version", *rOut.EksClusterCaCertificate)
		if err != nil {
			return err
		}
	}

	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}

	if rOut.Metadata != nil {
		err = d.Set("description", *rOut.Metadata)
		if err != nil {
			return err
		}
	}

	if len(rOut.ItemCustomFieldsDetails) > 0 {
		customFields := make(map[string]string)
		for _, field := range rOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		if len(customFields) > 0 {
			err = d.Set("item_custom_fields", customFields)
			if err != nil {
				return err
			}
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceDynamicSecretEksUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
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
	eksRegion := d.Get("eks_region").(string)
	eksAssumeRole := d.Get("eks_assume_role").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessClusterEndpoint := d.Get("secure_access_cluster_endpoint").(string)
	secureAccessAllowPortForwading := d.Get("secure_access_allow_port_forwading").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	if secureAccessCertificateIssuer == "" {
		secureAccessCertificateIssuer = d.Get("secure_access_bastion_issuer").(string)
	}
	secureAccessDelay := d.Get("secure_access_delay").(int)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.DynamicSecretUpdateEks{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.EksClusterName, eksClusterName)
	common.GetAkeylessPtr(&body.EksClusterEndpoint, eksClusterEndpoint)
	common.GetAkeylessPtr(&body.EksClusterCaCert, eksClusterCaCert)
	common.GetAkeylessPtr(&body.EksAccessKeyId, eksAccessKeyId)
	common.GetAkeylessPtr(&body.EksSecretAccessKey, eksSecretAccessKey)
	common.GetAkeylessPtr(&body.EksRegion, eksRegion)
	common.GetAkeylessPtr(&body.EksAssumeRole, eksAssumeRole)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ItemCustomFields, itemCustomFields)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessClusterEndpoint, secureAccessClusterEndpoint)
	common.GetAkeylessPtr(&body.SecureAccessAllowPortForwading, secureAccessAllowPortForwading)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessDelay, int64(secureAccessDelay))
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, resp, err := client.DynamicSecretUpdateEks(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretEksDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretEksImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretEksRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
