// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceK8sAuthConfig() *schema.Resource {
	return &schema.Resource{
		Description: "K8S Auth config",
		Create:      resourceK8sAuthConfigCreate,
		Read:        resourceK8sAuthConfigRead,
		Update:      resourceK8sAuthConfigUpdate,
		Delete:      resourceK8sAuthConfigDelete,
		Importer: &schema.ResourceImporter{
			State: resourceK8sAuthConfigImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "K8S Auth config name",
				ForceNew:    true,
			},
			"config_encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Encrypt K8S Auth config with following key",
			},
			"access_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The access ID of the Kubernetes auth method",
			},
			"signing_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The private key (in base64 encoded of the PEM format) associated with the public key defined in the Kubernetes auth",
			},
			"token_exp": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Time in seconds of expiration of the Akeyless Kube Auth Method token",
				Default:     "300",
			},
			"k8s_host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The URL of the kubernetes API server",
			},
			"k8s_ca_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The CA Certificate (base64 encoded) to use to call into the kubernetes API server",
			},
			"token_reviewer_jwt": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A Kubernetes service account JWT used to access the TokenReview API to validate other JWTs. If not set, the JWT submitted in the authentication process will be used to access the Kubernetes TokenReview API.",
			},
			"k8s_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Kubernetes JWT issuer name. If not set, this <kubernetes/serviceaccount> will be used by default.",
				Default:     "kubernetes/serviceaccount",
			},
			"disable_issuer_validation": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "false",
				Description: "Disable issuer validation [true/false]",
			},
			"cluster_api_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Cluster access type. options: [native_k8s, rancher]",
				Default:     "native_k8s",
			},
			"rancher_api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The api key used to access the TokenReview API to validate other JWTs (relevant for rancher only)",
			},
			"rancher_cluster_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The cluster id as define in rancher (relevant for rancher only)",
			},
		},
	}
}

func resourceK8sAuthConfigCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	configEncryptionKeyName := d.Get("config_encryption_key_name").(string)
	accessId := d.Get("access_id").(string)
	signingKey := d.Get("signing_key").(string)
	tokenExp := d.Get("token_exp").(int)
	k8sHost := d.Get("k8s_host").(string)
	k8sCaCert := d.Get("k8s_ca_cert").(string)
	tokenReviewerJwt := d.Get("token_reviewer_jwt").(string)
	k8sIssuer := d.Get("k8s_issuer").(string)
	disableIssValidation := d.Get("disable_issuer_validation").(string)

	clusterApiType := d.Get("cluster_api_type").(string)
	rancherApiKey := d.Get("rancher_api_key").(string)
	rancherClusterId := d.Get("rancher_cluster_id").(string)

	body := akeyless.GatewayCreateK8SAuthConfig{
		Name:     name,
		AccessId: accessId,
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.ConfigEncryptionKeyName, configEncryptionKeyName)
	common.GetAkeylessPtr(&body.SigningKey, signingKey)
	common.GetAkeylessPtr(&body.TokenExp, tokenExp)
	common.GetAkeylessPtr(&body.K8sHost, k8sHost)
	common.GetAkeylessPtr(&body.K8sCaCert, k8sCaCert)
	common.GetAkeylessPtr(&body.TokenReviewerJwt, tokenReviewerJwt)
	common.GetAkeylessPtr(&body.K8sIssuer, k8sIssuer)
	common.GetAkeylessPtr(&body.DisableIssuerValidation, disableIssValidation)

	common.GetAkeylessPtr(&body.ClusterApiType, clusterApiType)
	common.GetAkeylessPtr(&body.RancherApiKey, rancherApiKey)
	common.GetAkeylessPtr(&body.RancherClusterId, rancherClusterId)

	_, _, err := client.GatewayCreateK8SAuthConfig(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceK8sAuthConfigRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GatewayGetK8SAuthConfig{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GatewayGetK8SAuthConfig(ctx).Body(body).Execute()
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
	if rOut.Name != nil {
		err = d.Set("name", *rOut.Name)
		if err != nil {
			return err
		}
	}
	if rOut.K8sHost != nil {
		err = d.Set("k8s_host", *rOut.K8sHost)
		if err != nil {
			return err
		}
	}
	if rOut.K8sCaCert != nil {
		err = d.Set("k8s_ca_cert", *rOut.K8sCaCert)
		if err != nil {
			return err
		}
	}
	if rOut.K8sIssuer != nil {
		err = d.Set("k8s_issuer", *rOut.K8sIssuer)
		if err != nil {
			return err
		}
	}
	if rOut.DisableIssValidation != nil {
		err = d.Set("disable_issuer_validation", strconv.FormatBool(*rOut.DisableIssValidation))
		if err != nil {
			return err
		}
	}
	if rOut.ProtectionKey != nil {
		err = d.Set("config_encryption_key_name", *rOut.ProtectionKey)
		if err != nil {
			return err
		}
	}
	if rOut.AuthMethodAccessId != nil {
		err = d.Set("access_id", *rOut.AuthMethodAccessId)
		if err != nil {
			return err
		}
	}
	if rOut.K8sTokenReviewerJwt != nil {
		err = d.Set("token_reviewer_jwt", *rOut.K8sTokenReviewerJwt)
		if err != nil {
			return err
		}
	}

	if rOut.AuthMethodPrvKeyPem != nil {
		err = d.Set("signing_key", *rOut.AuthMethodPrvKeyPem)
		if err != nil {
			return err
		}
	}
	if rOut.AmTokenExpiration != nil {
		err = d.Set("token_exp", *rOut.AmTokenExpiration)
		if err != nil {
			return err
		}
	}

	if rOut.ClusterApiType != nil {
		err = d.Set("cluster_api_type", *rOut.ClusterApiType)
		if err != nil {
			return err
		}
	}
	if rOut.RancherApiKey != nil {
		err = d.Set("rancher_api_key", *rOut.RancherApiKey)
		if err != nil {
			return err
		}
	}
	if rOut.RancherClusterId != nil {
		err = d.Set("rancher_cluster_id", *rOut.RancherClusterId)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceK8sAuthConfigUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	configEncryptionKeyName := d.Get("config_encryption_key_name").(string)
	accessId := d.Get("access_id").(string)
	signingKey := d.Get("signing_key").(string)
	tokenExp := d.Get("token_exp").(int)
	k8sHost := d.Get("k8s_host").(string)
	k8sCaCert := d.Get("k8s_ca_cert").(string)
	tokenReviewerJwt := d.Get("token_reviewer_jwt").(string)
	k8sIssuer := d.Get("k8s_issuer").(string)
	disableIssValidation := d.Get("disable_issuer_validation").(string)

	clusterApiType := d.Get("cluster_api_type").(string)
	rancherApiKey := d.Get("rancher_api_key").(string)
	rancherClusterId := d.Get("rancher_cluster_id").(string)

	body := akeyless.GatewayUpdateK8SAuthConfig{
		Name:     name,
		AccessId: accessId,
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.ConfigEncryptionKeyName, configEncryptionKeyName)
	common.GetAkeylessPtr(&body.SigningKey, signingKey)
	common.GetAkeylessPtr(&body.TokenExp, tokenExp)
	common.GetAkeylessPtr(&body.K8sHost, k8sHost)
	common.GetAkeylessPtr(&body.K8sCaCert, k8sCaCert)
	common.GetAkeylessPtr(&body.TokenReviewerJwt, tokenReviewerJwt)
	common.GetAkeylessPtr(&body.K8sIssuer, k8sIssuer)
	common.GetAkeylessPtr(&body.DisableIssuerValidation, disableIssValidation)

	common.GetAkeylessPtr(&body.ClusterApiType, clusterApiType)
	common.GetAkeylessPtr(&body.RancherApiKey, rancherApiKey)
	common.GetAkeylessPtr(&body.RancherClusterId, rancherClusterId)

	_, _, err := client.GatewayUpdateK8SAuthConfig(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceK8sAuthConfigDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.GatewayDeleteK8SAuthConfig{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.GatewayDeleteK8SAuthConfig(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceK8sAuthConfigImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceK8sAuthConfigRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
