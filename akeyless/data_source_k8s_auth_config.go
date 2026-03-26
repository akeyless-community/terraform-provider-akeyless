package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGatewayGetK8sAuthConfig() *schema.Resource {
	return &schema.Resource{
		Description: "Gets K8S Auth config data source",
		Read:        dataSourceGatewayGetK8sAuthConfigRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "K8S Auth config name",
				ForceNew:    true,
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "K8S Auth config ID",
			},
			"protection_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "The name of the key that protects the K8S Auth config",
			},
			"auth_method_access_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "AuthMethodAccessId of the Kubernetes auth method",
			},
			"auth_method_prv_key_pem": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Sensitive:   true,
				Description: "AuthMethodSigningKey is the private key (in base64 of the PEM format) associated with the public key defined in the Kubernetes auth method, that used to sign the internal token for the Akeyless Kubernetes Auth Method",
			},
			"am_token_expiration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Required:    false,
				Description: "AuthMethodTokenExpiration is time in seconds of expiration of the Akeyless Kube Auth Method token",
			},
			"k8s_host": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "K8SHost is the url string for the kubernetes API",
			},
			"k8s_ca_cert": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "K8SCACert is the CA Cert to use to call into the kubernetes API",
			},
			"k8s_token_reviewer_jwt": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "K8STokenReviewerJWT is the bearer for clusterApiTypeK8s, used during TokenReview API call",
			},
			"k8s_issuer": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "K8SIssuer is the claim that specifies who issued the Kubernetes token",
			},
			"k8s_pub_keys_pem": {
				Type:        schema.TypeSet,
				Computed:    true,
				Required:    false,
				Description: "K8SPublicKeysPEM is the list of public key in PEM format",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"disable_iss_validation": {
				Type:        schema.TypeBool,
				Computed:    true,
				Required:    false,
				Description: "DisableISSValidation is optional parameter to disable ISS validation",
			},
			"use_local_ca_jwt": {
				Type:        schema.TypeBool,
				Computed:    true,
				Required:    false,
				Description: "UseLocalCAJwt is an optional parameter to set defaulting to using the local service account when running in a Kubernetes pod",
			},
			"cluster_api_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "Defines types of API access to cluster",
			},
			"k8s_auth_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "Kubernetes authentication type",
			},
			"k8s_client_cert_data": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "K8sClientCertData is the client certificate for k8s client certificate authentication",
			},
			"k8s_client_key_data": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "K8sClientKeyData is the client key for k8s client certificate authentication",
			},
			"rancher_api_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "RancherApiKey the bear token for clusterApiTypeRancher",
			},
			"rancher_cluster_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "RancherClusterId cluster id as define in rancher (in case of clusterApiTypeRancher)",
			},
		},
	}
}

func dataSourceGatewayGetK8sAuthConfigRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.GatewayGetK8SAuthConfig{
		Name:  name,
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
	if rOut.Id != nil {
		err = d.Set("id", *rOut.Id)
		if err != nil {
			return err
		}
	}
	if rOut.ProtectionKey != nil {
		err = d.Set("protection_key", *rOut.ProtectionKey)
		if err != nil {
			return err
		}
	}
	if rOut.AuthMethodAccessId != nil {
		err = d.Set("auth_method_access_id", *rOut.AuthMethodAccessId)
		if err != nil {
			return err
		}
	}
	if rOut.AuthMethodPrvKeyPem != nil {
		err = d.Set("auth_method_prv_key_pem", *rOut.AuthMethodPrvKeyPem)
		if err != nil {
			return err
		}
	}
	if rOut.AmTokenExpiration != nil {
		err = d.Set("am_token_expiration", *rOut.AmTokenExpiration)
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
	if rOut.K8sTokenReviewerJwt != nil {
		err = d.Set("k8s_token_reviewer_jwt", *rOut.K8sTokenReviewerJwt)
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
	if rOut.K8sPubKeysPem != nil {
		err = d.Set("k8s_pub_keys_pem", rOut.K8sPubKeysPem)
		if err != nil {
			return err
		}
	}
	if rOut.DisableIssValidation != nil {
		err = d.Set("disable_iss_validation", *rOut.DisableIssValidation)
		if err != nil {
			return err
		}
	}
	if rOut.UseLocalCaJwt != nil {
		err = d.Set("use_local_ca_jwt", *rOut.UseLocalCaJwt)
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
	if rOut.K8sAuthType != nil {
		err = d.Set("k8s_auth_type", *rOut.K8sAuthType)
		if err != nil {
			return err
		}
	}
	if rOut.K8sClientCertData != nil {
		err = d.Set("k8s_client_cert_data", *rOut.K8sClientCertData)
		if err != nil {
			return err
		}
	}
	if rOut.K8sClientKeyData != nil {
		err = d.Set("k8s_client_key_data", *rOut.K8sClientKeyData)
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

	d.SetId(name)
	return nil
}
