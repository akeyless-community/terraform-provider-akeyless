package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAuthMethodK8s() *schema.Resource {
	return &schema.Resource{
		Description: "Kubernetes Auth Method Resource",
		Create:      resourceAuthMethodK8sCreate,
		Read:        resourceAuthMethodK8sRead,
		Update:      resourceAuthMethodK8sUpdate,
		Delete:      resourceAuthMethodK8sDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodK8sImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Auth Method name",
				ForceNew:    true,
			},
			"access_expires": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Access expiration date in Unix timestamp (select 0 for access without expiry date)",
				Default:     0,
			},
			"bound_ips": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "A CIDR whitelist with the IPs that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"force_sub_claims": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "enforce role-association must include sub claims",
			},
			"gen_key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "If this flag is set to true, there is no need to manually provide a public key for the Kubernetes Auth Method, and instead, a key pair, will be generated as part of the command and the private part of the key will be returned (the private key is required for the K8S Auth Config in the Akeyless Gateway)",
				Default:     "true",
			},
			"audience": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The audience in the Kubernetes JWT that the access is restricted to",
			},
			"bound_sa_names": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "A list of service account names that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_pod_names": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "A list of pod names that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_namespaces": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "A list of namespaces that the access is restricted to",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"access_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Auth Method access ID",
			},
			"private_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The Private Key",
			},
			"public_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The public key",
			},
		},
	}
}

func resourceAuthMethodK8sCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	accessExpires := d.Get("access_expires").(int)
	publicKey := d.Get("public_key").(string)
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	genKey := d.Get("gen_key").(string)
	audience := d.Get("audience").(string)
	boundSaNamesSet := d.Get("bound_sa_names").(*schema.Set)
	boundSaNames := common.ExpandStringList(boundSaNamesSet.List())
	boundPodNamesSet := d.Get("bound_pod_names").(*schema.Set)
	boundPodNames := common.ExpandStringList(boundPodNamesSet.List())
	boundNamespacesSet := d.Get("bound_namespaces").(*schema.Set)
	boundNamespaces := common.ExpandStringList(boundNamespacesSet.List())

	body := akeyless.CreateAuthMethodK8S{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.GenKey, "false")
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.Audience, audience)
	common.GetAkeylessPtr(&body.BoundSaNames, boundSaNames)
	common.GetAkeylessPtr(&body.BoundPodNames, boundPodNames)
	common.GetAkeylessPtr(&body.BoundNamespaces, boundNamespaces)
	common.GetAkeylessPtr(&body.PublicKey, publicKey)
	common.GetAkeylessPtr(&body.GenKey, genKey)

	rOut, _, err := client.CreateAuthMethodK8S(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	if rOut.AccessId != nil {
		err = d.Set("access_id", *rOut.AccessId)
		if err != nil {
			return err
		}
	}

	if rOut.PrvKey != nil {
		err = d.Set("private_key", *rOut.PrvKey)
		if err != nil {
			return err
		}
	}
	if publicKey == "" {
		body := akeyless.GetAuthMethod{
			Name:  name,
			Token: &token,
		}
		rOut, _, err := client.GetAuthMethod(ctx).Body(body).Execute()
		if err == nil {
			if rOut.AccessInfo.K8sAccessRules.PubKey != nil {
				err = d.Set("public_key", *rOut.AccessInfo.K8sAccessRules.PubKey)
				if err != nil {
					return err
				}
			}
		}
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodK8sRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GetAuthMethod{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GetAuthMethod(ctx).Body(body).Execute()
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
	if rOut.AuthMethodAccessId != nil {
		err = d.Set("access_id", *rOut.AuthMethodAccessId)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.AccessExpires != nil {
		err = d.Set("access_expires", *rOut.AccessInfo.AccessExpires)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.ForceSubClaims != nil {
		err = d.Set("force_sub_claims", *rOut.AccessInfo.ForceSubClaims)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.CidrWhitelist != nil && *rOut.AccessInfo.CidrWhitelist != "" {

		err = d.Set("bound_ips", strings.Split(*rOut.AccessInfo.CidrWhitelist, ","))
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.K8sAccessRules.PubKey != nil {
		err = d.Set("public_key", *rOut.AccessInfo.K8sAccessRules.PubKey)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.K8sAccessRules.Audience != nil {
		err = d.Set("audience", *rOut.AccessInfo.K8sAccessRules.Audience)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.K8sAccessRules.BoundPodNames != nil {
		err = d.Set("bound_pod_names", *rOut.AccessInfo.K8sAccessRules.BoundPodNames)
		if err != nil {
			return err
		}
	}
	if rOut.AccessInfo.K8sAccessRules.BoundNamespaces != nil {
		err = d.Set("bound_namespaces", *rOut.AccessInfo.K8sAccessRules.BoundNamespaces)
		if err != nil {
			return err
		}
	}

	if rOut.AccessInfo.K8sAccessRules.BoundServiceAccountNames != nil {
		err = d.Set("bound_sa_names", *rOut.AccessInfo.K8sAccessRules.BoundServiceAccountNames)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceAuthMethodK8sUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	accessExpires := d.Get("access_expires").(int)
	publicKey := d.Get("public_key").(string)
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	audience := d.Get("audience").(string)
	boundSaNamesSet := d.Get("bound_sa_names").(*schema.Set)
	boundSaNames := common.ExpandStringList(boundSaNamesSet.List())
	boundPodNamesSet := d.Get("bound_pod_names").(*schema.Set)
	boundPodNames := common.ExpandStringList(boundPodNamesSet.List())
	boundNamespacesSet := d.Get("bound_namespaces").(*schema.Set)
	boundNamespaces := common.ExpandStringList(boundNamespacesSet.List())

	body := akeyless.UpdateAuthMethodK8S{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.Audience, audience)
	common.GetAkeylessPtr(&body.BoundSaNames, boundSaNames)
	common.GetAkeylessPtr(&body.BoundPodNames, boundPodNames)
	common.GetAkeylessPtr(&body.BoundNamespaces, boundNamespaces)
	common.GetAkeylessPtr(&body.PublicKey, publicKey)
	common.GetAkeylessPtr(&body.GenKey, "false")

	_, _, err := client.UpdateAuthMethodK8S(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodK8sDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteAuthMethod{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteAuthMethod(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceAuthMethodK8sImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GetAuthMethod{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GetAuthMethod(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
