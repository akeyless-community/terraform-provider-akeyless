// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceProducerK8s() *schema.Resource {
	return &schema.Resource{
		Description:        "Native Kubernetes Service producer resource",
		DeprecationMessage: "Deprecated: Please use new resource: akeyless_dynamic_secret_k8s",
		Create:             resourceProducerK8sCreate,
		Read:               resourceProducerK8sRead,
		Update:             resourceProducerK8sUpdate,
		Delete:             resourceProducerK8sDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerK8sImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Producer name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of existing target to use in producer creation",
			},
			"k8s_cluster_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "K8S Cluster endpoint. https:// , <DNS / IP> of the cluster.",
			},
			"k8s_cluster_ca_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "K8S Cluster certificate. Base 64 encoded certificate.",
			},
			"k8s_cluster_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "K8S Cluster authentication token.",
			},
			"k8s_service_account": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "K8S ServiceAccount to extract token from.",
			},
			"k8s_namespace": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "K8S Namespace where the ServiceAccount exists.",
				Default:     "default",
			},
			"k8s_service_account_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "K8S ServiceAccount type [fixed, dynamic].",
				Default:     "fixed",
			},
			"k8s_allowed_namespaces": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Comma-separated list of allowed K8S namespaces for the generated ServiceAccount (relevant only for k8s-service-account-type=dynamic).",
			},
			"k8s_predefined_role_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The pre-existing Role or ClusterRole name to bind the generated ServiceAccount to (relevant only for k8s-service-account-type=dynamic).",
			},
			"k8s_predefined_role_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the type of the pre-existing K8S role [Role, ClusterRole] (relevant only for k8s-service-account-type=dynamic).",
			},
			"producer_encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Encrypt producer with following key",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: --tag Tag1 --tag Tag2",
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
				Description: "The K8s cluster endpoint",
			},
			"secure_access_dashboard_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The K8s dashboard url",
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
			"secure_access_web_browsing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Secure browser via Akeyless Web Access Bastion",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable Web Secure Remote Access",
				Default:     "false",
			},
			"secure_access_web_proxy": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Web-Proxy via Akeyless Web Access Bastion",
				Default:     "false",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this item [true/false]",
			},
		},
	}
}

func resourceProducerK8sCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	k8sClusterEndpoint := d.Get("k8s_cluster_endpoint").(string)
	k8sClusterCaCert := d.Get("k8s_cluster_ca_cert").(string)
	k8sClusterToken := d.Get("k8s_cluster_token").(string)
	k8sServiceAccount := d.Get("k8s_service_account").(string)
	k8sNamespace := d.Get("k8s_namespace").(string)
	k8sServiceAccountType := d.Get("k8s_service_account_type").(string)
	k8sAllowedNamespaces := d.Get("k8s_allowed_namespaces").(string)
	k8sPredefinedRoleName := d.Get("k8s_predefined_role_name").(string)
	k8sPredefinedRoleType := d.Get("k8s_predefined_role_type").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessClusterEndpoint := d.Get("secure_access_cluster_endpoint").(string)
	secureAccessDashboardUrl := d.Get("secure_access_dashboard_url").(string)
	secureAccessAllowPortForwading := d.Get("secure_access_allow_port_forwading").(bool)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless.GatewayCreateProducerNativeK8S{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.K8sClusterEndpoint, k8sClusterEndpoint)
	common.GetAkeylessPtr(&body.K8sClusterCaCert, k8sClusterCaCert)
	common.GetAkeylessPtr(&body.K8sClusterToken, k8sClusterToken)
	common.GetAkeylessPtr(&body.K8sServiceAccount, k8sServiceAccount)
	common.GetAkeylessPtr(&body.K8sNamespace, k8sNamespace)
	common.GetAkeylessPtr(&body.K8sServiceAccountType, k8sServiceAccountType)
	common.GetAkeylessPtr(&body.K8sAllowedNamespaces, k8sAllowedNamespaces)
	common.GetAkeylessPtr(&body.K8sPredefinedRoleName, k8sPredefinedRoleName)
	common.GetAkeylessPtr(&body.K8sPredefinedRoleType, k8sPredefinedRoleType)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessClusterEndpoint, secureAccessClusterEndpoint)
	common.GetAkeylessPtr(&body.SecureAccessDashboardUrl, secureAccessDashboardUrl)
	common.GetAkeylessPtr(&body.SecureAccessAllowPortForwading, secureAccessAllowPortForwading)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.GatewayCreateProducerNativeK8S(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Producer: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create producer: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerK8sRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.K8sClusterEndpoint != nil {
		err = d.Set("k8s_cluster_endpoint", *rOut.K8sClusterEndpoint)
		if err != nil {
			return err
		}
	}
	if rOut.K8sServiceAccount != nil {
		err = d.Set("k8s_service_account", *rOut.K8sServiceAccount)
		if err != nil {
			return err
		}
	}
	if rOut.K8sNamespace != nil {
		err = d.Set("k8s_namespace", *rOut.K8sNamespace)
		if err != nil {
			return err
		}
	}
	if rOut.K8sDynamicMode != nil {
		k8sServiceAccountType := getServiceAccountType(*rOut.K8sDynamicMode)
		err = d.Set("k8s_service_account_type", k8sServiceAccountType)
		if err != nil {
			return err
		}
	}
	if rOut.K8sAllowedNamespaces != nil {
		err = d.Set("k8s_allowed_namespaces", *rOut.K8sAllowedNamespaces)
		if err != nil {
			return err
		}
	}
	if rOut.K8sRoleName != nil {
		err = d.Set("k8s_predefined_role_name", *rOut.K8sRoleName)
		if err != nil {
			return err
		}
	}
	if rOut.K8sRoleType != nil {
		serviceAccountType, err := getServiceAccountPredefinedRoleType(*rOut.K8sRoleType)
		if err != nil {
			return err
		}

		err = d.Set("k8s_predefined_role_type", serviceAccountType)
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

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
		if err != nil {
			return err
		}
	}

	if rOut.K8sClusterCaCertificate != nil {
		err = d.Set("k8s_cluster_ca_cert", *rOut.K8sClusterCaCertificate)
		if err != nil {
			return err
		}
	}
	if rOut.K8sBearerToken != nil {
		err = d.Set("k8s_cluster_token", *rOut.K8sBearerToken)
		if err != nil {
			return err
		}
	}
	if rOut.DynamicSecretKey != nil {
		err = d.Set("producer_encryption_key_name", *rOut.DynamicSecretKey)
		if err != nil {
			return err
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceProducerK8sUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	k8sClusterEndpoint := d.Get("k8s_cluster_endpoint").(string)
	k8sClusterCaCert := d.Get("k8s_cluster_ca_cert").(string)
	k8sClusterToken := d.Get("k8s_cluster_token").(string)
	k8sServiceAccount := d.Get("k8s_service_account").(string)
	k8sNamespace := d.Get("k8s_namespace").(string)
	k8sServiceAccountType := d.Get("k8s_service_account_type").(string)
	k8sAllowedNamespaces := d.Get("k8s_allowed_namespaces").(string)
	k8sPredefinedRoleName := d.Get("k8s_predefined_role_name").(string)
	k8sPredefinedRoleType := d.Get("k8s_predefined_role_type").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessClusterEndpoint := d.Get("secure_access_cluster_endpoint").(string)
	secureAccessDashboardUrl := d.Get("secure_access_dashboard_url").(string)
	secureAccessAllowPortForwading := d.Get("secure_access_allow_port_forwading").(bool)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless.GatewayUpdateProducerNativeK8S{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.K8sClusterEndpoint, k8sClusterEndpoint)
	common.GetAkeylessPtr(&body.K8sClusterCaCert, k8sClusterCaCert)
	common.GetAkeylessPtr(&body.K8sClusterToken, k8sClusterToken)
	common.GetAkeylessPtr(&body.K8sServiceAccount, k8sServiceAccount)
	common.GetAkeylessPtr(&body.K8sNamespace, k8sNamespace)
	common.GetAkeylessPtr(&body.K8sServiceAccountType, k8sServiceAccountType)
	common.GetAkeylessPtr(&body.K8sAllowedNamespaces, k8sAllowedNamespaces)
	common.GetAkeylessPtr(&body.K8sPredefinedRoleName, k8sPredefinedRoleName)
	common.GetAkeylessPtr(&body.K8sPredefinedRoleType, k8sPredefinedRoleType)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessClusterEndpoint, secureAccessClusterEndpoint)
	common.GetAkeylessPtr(&body.SecureAccessDashboardUrl, secureAccessDashboardUrl)
	common.GetAkeylessPtr(&body.SecureAccessAllowPortForwading, secureAccessAllowPortForwading)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.GatewayUpdateProducerNativeK8S(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update Producer: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update producer: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerK8sDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.GatewayDeleteProducer{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.GatewayDeleteProducer(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceProducerK8sImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceProducerK8sRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func getServiceAccountPredefinedRoleType(oldType string) (string, error) {
	switch oldType {
	case "k8s_role", "Role":
		return "Role", nil
	case "k8s_cluster_role", "ClusterRole":
		return "ClusterRole", nil
	default:
		return "", fmt.Errorf("unknown type of k8s-service-account")
	}
}

func getServiceAccountType(isDinamicMode bool) string {
	if isDinamicMode {
		return "dynamic"
	}
	return "fixed"
}
