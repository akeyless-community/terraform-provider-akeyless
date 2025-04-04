// generated fule
package akeyless

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
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
			"gke_service_account_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GKE service account email",
			},
			"gke_cluster_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GKE cluster endpoint, i.e., cluster URI https://<DNS/IP>.",
			},
			"gke_cluster_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GKE Base-64 encoded cluster certificate",
			},
			"gke_account_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GKE service account key",
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

func resourceDynamicSecretGkeCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
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
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.DynamicSecretCreateGke{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
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
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.DynamicSecretCreateGke(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretGkeRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
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

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
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
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.DynamicSecretUpdateGke{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
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
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.DynamicSecretUpdateGke(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
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
