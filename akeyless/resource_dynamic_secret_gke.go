// generated file
package akeyless

import (
	"context"
	"encoding/base64"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretGke() *schema.Resource {
	return &schema.Resource{
		Description: "Google Kubernetes Engine (GKE) dynamic secret resource",
		Create:      resourceDynamicSecretGkeCreate,
		Read:        resourceDynamicSecretGkeRead,
		Update:      resourceDynamicSecretGkeUpdate,
		Delete:      resourceDynamicSecretGkeDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretGkeImport,
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
			"gke_service_account_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GKE service account email",
			},
			"gke_cluster_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GKE cluster URL endpoint",
			},
			"gke_cluster_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GKE cluster CA certificate",
			},
			"gke_account_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GKE Service Account key file path",
			},
			"gke_cluster_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GKE cluster name",
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
				Description: "Dynamic producer encryption key",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
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

func resourceDynamicSecretGkeCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	gkeServiceAccountEmail := d.Get("gke_service_account_email").(string)
	gkeClusterEndpoint := d.Get("gke_cluster_endpoint").(string)
	gkeClusterCert := d.Get("gke_cluster_cert").(string)
	gkeAccountKey := d.Get("gke_account_key").(string)
	gkeClusterName := d.Get("gke_cluster_name").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessClusterEndpoint := d.Get("secure_access_cluster_endpoint").(string)
	secureAccessAllowPortForwading := d.Get("secure_access_allow_port_forwading").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	if secureAccessCertificateIssuer == "" {
		secureAccessCertificateIssuer = d.Get("secure_access_bastion_issuer").(string)
	}
	secureAccessDelay := int64(d.Get("secure_access_delay").(int))
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.DynamicSecretCreateGke{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		customFields := make(map[string]string)
		for k, v := range itemCustomFields {
			customFields[k] = v.(string)
		}
		common.GetAkeylessPtr(&body.ItemCustomFields, &customFields)
	}
	common.GetAkeylessPtr(&body.GkeServiceAccountEmail, gkeServiceAccountEmail)
	common.GetAkeylessPtr(&body.GkeClusterEndpoint, gkeClusterEndpoint)
	common.GetAkeylessPtr(&body.GkeClusterCert, gkeClusterCert)
	common.GetAkeylessPtr(&body.GkeAccountKey, gkeAccountKey)
	common.GetAkeylessPtr(&body.GkeClusterName, gkeClusterName)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessClusterEndpoint, secureAccessClusterEndpoint)
	common.GetAkeylessPtr(&body.SecureAccessAllowPortForwading, secureAccessAllowPortForwading)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessDelay, secureAccessDelay)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, resp, err := client.DynamicSecretCreateGke(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretGkeRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.GkeClusterEndpoint != nil {
		err = d.Set("gke_cluster_endpoint", *rOut.GkeClusterEndpoint)
		if err != nil {
			return err
		}
	}
	if rOut.GkeClusterName != nil {
		err = d.Set("gke_cluster_name", *rOut.GkeClusterName)
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

	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}

	if rOut.ItemCustomFieldsDetails != nil && len(rOut.ItemCustomFieldsDetails) > 0 {
		customFields := make(map[string]interface{})
		for _, field := range rOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		err = d.Set("item_custom_fields", customFields)
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

	if rOut.GkeServiceAccountName != nil {
		err = d.Set("gke_service_account_email", *rOut.GkeServiceAccountName)
		if err != nil {
			return err
		}
	}
	if rOut.GkeClusterCaCertificate != nil {
		err = d.Set("gke_cluster_cert", *rOut.GkeClusterCaCertificate)
		if err != nil {
			return err
		}
	}
	if rOut.GkeServiceAccountKey != nil {
		sDec := base64.StdEncoding.EncodeToString([]byte(*rOut.GkeServiceAccountKey))
		err = d.Set("gke_account_key", sDec)
		if err != nil {
			return err
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceDynamicSecretGkeUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	gkeServiceAccountEmail := d.Get("gke_service_account_email").(string)
	gkeClusterEndpoint := d.Get("gke_cluster_endpoint").(string)
	gkeClusterCert := d.Get("gke_cluster_cert").(string)
	gkeAccountKey := d.Get("gke_account_key").(string)
	gkeClusterName := d.Get("gke_cluster_name").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessClusterEndpoint := d.Get("secure_access_cluster_endpoint").(string)
	secureAccessAllowPortForwading := d.Get("secure_access_allow_port_forwading").(bool)
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	if secureAccessCertificateIssuer == "" {
		secureAccessCertificateIssuer = d.Get("secure_access_bastion_issuer").(string)
	}
	secureAccessDelay := int64(d.Get("secure_access_delay").(int))
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.DynamicSecretUpdateGke{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		customFields := make(map[string]string)
		for k, v := range itemCustomFields {
			customFields[k] = v.(string)
		}
		common.GetAkeylessPtr(&body.ItemCustomFields, &customFields)
	}
	common.GetAkeylessPtr(&body.GkeServiceAccountEmail, gkeServiceAccountEmail)
	common.GetAkeylessPtr(&body.GkeClusterEndpoint, gkeClusterEndpoint)
	common.GetAkeylessPtr(&body.GkeClusterCert, gkeClusterCert)
	common.GetAkeylessPtr(&body.GkeAccountKey, gkeAccountKey)
	common.GetAkeylessPtr(&body.GkeClusterName, gkeClusterName)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessClusterEndpoint, secureAccessClusterEndpoint)
	common.GetAkeylessPtr(&body.SecureAccessAllowPortForwading, secureAccessAllowPortForwading)
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	common.GetAkeylessPtr(&body.SecureAccessDelay, secureAccessDelay)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, resp, err := client.DynamicSecretUpdateGke(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretGkeDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretGkeImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretGkeRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
