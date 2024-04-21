// generated
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretEks() *schema.Resource {
	return &schema.Resource{
		Description: "Amazon Elastic Kubernetes Service (Amazon EKS) producer",
		Create:      resourceDynamicSecretEksCreate,
		Read:        resourceDynamicSecretEksRead,
		Update:      resourceDynamicSecretEksUpdate,
		Delete:      resourceDynamicSecretEksDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretEksImport,
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
				Description: "Name of existing target to use in producer creation",
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
				Description: "Encrypt dynamic secret details with following key",
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
			"secure_access_bastion_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Bastion",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     "false",
				Description: "Enable Web Secure Remote Access",
			},
		},
	}
}

func resourceDynamicSecretEksCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	eksClusterName := d.Get("eks_cluster_name").(string)
	eksClusterEndpoint := d.Get("eks_cluster_endpoint").(string)
	eksClusterCaCert := d.Get("eks_cluster_ca_cert").(string)
	eksAccessKeyId := d.Get("eks_access_key_id").(string)
	eksSecretAccessKey := d.Get("eks_secret_access_key").(string)
	eksRegion := d.Get("eks_region").(string)
	eksAssumeRole := d.Get("eks_assume_role").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessClusterEndpoint := d.Get("secure_access_cluster_endpoint").(string)
	secureAccessAllowPortForwading := d.Get("secure_access_allow_port_forwading").(bool)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.DynamicSecretCreateEks{
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
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessClusterEndpoint, secureAccessClusterEndpoint)
	common.GetAkeylessPtr(&body.SecureAccessAllowPortForwading, secureAccessAllowPortForwading)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.DynamicSecretCreateEks(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretEksRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GatewayGetProducer{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GatewayGetProducer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
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
		err = d.Set("eks_secret_access_key", *rOut.EksSecretAccessKey)
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
		err = d.Set("tags", *rOut.Tags)
		if err != nil {
			return err
		}
	}

	if rOut.DynamicSecretKey != nil {
		err = d.Set("encryption_key_name", *rOut.DynamicSecretKey)
		if err != nil {
			return err
		}
	}

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
		if err != nil {
			return err
		}
	}

	if rOut.EksClusterCaCertificate != nil {
		err = d.Set("eks_cluster_ca_cert", *rOut.EksClusterCaCertificate)
		if err != nil {
			return err
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceDynamicSecretEksUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	eksClusterName := d.Get("eks_cluster_name").(string)
	eksClusterEndpoint := d.Get("eks_cluster_endpoint").(string)
	eksClusterCaCert := d.Get("eks_cluster_ca_cert").(string)
	eksAccessKeyId := d.Get("eks_access_key_id").(string)
	eksSecretAccessKey := d.Get("eks_secret_access_key").(string)
	eksRegion := d.Get("eks_region").(string)
	eksAssumeRole := d.Get("eks_assume_role").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessClusterEndpoint := d.Get("secure_access_cluster_endpoint").(string)
	secureAccessAllowPortForwading := d.Get("secure_access_allow_port_forwading").(bool)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.DynamicSecretUpdateEks{
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
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessClusterEndpoint, secureAccessClusterEndpoint)
	common.GetAkeylessPtr(&body.SecureAccessAllowPortForwading, secureAccessAllowPortForwading)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.DynamicSecretUpdateEks(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretEksDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretEksImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	return resourceDynamicSecretImport(d, m)
}
