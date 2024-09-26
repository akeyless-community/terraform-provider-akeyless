package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
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
				Description: "",
			},
			"protection_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"auth_method_access_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"auth_method_prv_key_pem": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Sensitive:   true,
				Description: "",
			},
			"am_token_expiration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"k8s_host": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"k8s_ca_cert": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"k8s_token_reviewer_jwt": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"k8s_issuer": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"k8s_pub_keys_pem": {
				Type:        schema.TypeSet,
				Computed:    true,
				Required:    false,
				Description: "",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"disable_iss_validation": {
				Type:        schema.TypeBool,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"use_local_ca_jwt": {
				Type:        schema.TypeBool,
				Computed:    true,
				Required:    false,
				Description: "",
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
		err = d.Set("k8s_pub_keys_pem", *rOut.K8sPubKeysPem)
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

	d.SetId(name)
	return nil
}
