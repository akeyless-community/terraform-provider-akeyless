package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSalesforceTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Salesforce Target resource",
		Create:      resourceSalesforceTargetCreate,
		Read:        resourceSalesforceTargetRead,
		Update:      resourceSalesforceTargetUpdate,
		Delete:      resourceSalesforceTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceSalesforceTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"auth_flow": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "type of the auth flow ('jwt' / 'user-password')",
			},
			"client_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Client ID of the oauth2 app to use for connecting to Salesforce",
			},
			"email": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The email of the user attached to the oauth2 app used for connecting to Salesforce",
			},
			"tenant_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Url of the Salesforce tenant",
			},
			"client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Client secret of the oauth2 app to use for connecting to Salesforce (required for password flow)",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "The password of the user attached to the oauth2 app used for connecting to Salesforce (required for user-password flow)",
			},
			"security_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "The security token of the user attached to the oauth2 app used for connecting to Salesforce  (required for user-password flow)",
			},
			"app_private_key_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Base64 encoded PEM of the connected app private key (relevant for JWT auth only)",
			},
			"ca_cert_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base64 encoded PEM cert to use when uploading a new key to Salesforce",
			},
			"ca_cert_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "name of the certificate in Salesforce tenant to use when uploading new key",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of a key that used to encrypt the target secret value (if empty, the account default protectionKey key will be used)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceSalesforceTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	authFlow := d.Get("auth_flow").(string)
	clientId := d.Get("client_id").(string)
	email := d.Get("email").(string)
	tenantUrl := d.Get("tenant_url").(string)
	clientSecret := d.Get("client_secret").(string)
	password := d.Get("password").(string)
	securityToken := d.Get("security_token").(string)
	appPrivateKeyData := d.Get("app_private_key_data").(string)
	caCertData := d.Get("ca_cert_data").(string)
	caCertName := d.Get("ca_cert_name").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.CreateSalesforceTarget{
		Name:      name,
		AuthFlow:  authFlow,
		ClientId:  clientId,
		Email:     email,
		TenantUrl: tenantUrl,
		Token:     &token,
	}
	common.GetAkeylessPtr(&body.ClientSecret, clientSecret)
	common.GetAkeylessPtr(&body.Password, password)
	common.GetAkeylessPtr(&body.SecurityToken, securityToken)
	common.GetAkeylessPtr(&body.AppPrivateKeyData, appPrivateKeyData)
	common.GetAkeylessPtr(&body.CaCertData, caCertData)
	common.GetAkeylessPtr(&body.CaCertName, caCertName)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.CreateSalesforceTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceSalesforceTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("failed to get target details: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to get target details: %w", err)
	}

	if rOut.Value != nil {
		targetDetails := *rOut.Value

		if targetDetails.SalesforceTargetDetails != nil {
			if targetDetails.SalesforceTargetDetails.AuthFlow != nil {
				// Normalize auth_flow to lowercase
				authFlow := strings.ToLower(*targetDetails.SalesforceTargetDetails.AuthFlow)
				err := d.Set("auth_flow", authFlow)
				if err != nil {
					return err
				}
			}
			if targetDetails.SalesforceTargetDetails.ClientId != nil {
				err := d.Set("client_id", *targetDetails.SalesforceTargetDetails.ClientId)
				if err != nil {
					return err
				}
			}
			if targetDetails.SalesforceTargetDetails.UserName != nil {
				err := d.Set("email", *targetDetails.SalesforceTargetDetails.UserName)
				if err != nil {
					return err
				}
			}
			if targetDetails.SalesforceTargetDetails.TenantUrl != nil {
				err := d.Set("tenant_url", *targetDetails.SalesforceTargetDetails.TenantUrl)
				if err != nil {
					return err
				}
			}
			if targetDetails.SalesforceTargetDetails.ClientSecret != nil {
				err := d.Set("client_secret", *targetDetails.SalesforceTargetDetails.ClientSecret)
				if err != nil {
					return err
				}
			}
			if targetDetails.SalesforceTargetDetails.Password != nil {
				err := d.Set("password", *targetDetails.SalesforceTargetDetails.Password)
				if err != nil {
					return err
				}
			}
			if targetDetails.SalesforceTargetDetails.SecurityToken != nil {
				err := d.Set("security_token", *targetDetails.SalesforceTargetDetails.SecurityToken)
				if err != nil {
					return err
				}
			}
			// Note: AppPrivateKey and CaCertData are byte arrays in the API
			// For simplicity, we skip reading them back
			if targetDetails.SalesforceTargetDetails.CaCertName != nil {
				err := d.Set("ca_cert_name", *targetDetails.SalesforceTargetDetails.CaCertName)
				if err != nil {
					return err
				}
			}
		}
	}

	if rOut.Target != nil {
		target := *rOut.Target

		if target.Comment != nil {
			err := d.Set("description", *target.Comment)
			if err != nil {
				return err
			}
		}
		if target.ProtectionKeyName != nil {
			err = d.Set("key", *target.ProtectionKeyName)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceSalesforceTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	authFlow := d.Get("auth_flow").(string)
	clientId := d.Get("client_id").(string)
	email := d.Get("email").(string)
	tenantUrl := d.Get("tenant_url").(string)
	clientSecret := d.Get("client_secret").(string)
	password := d.Get("password").(string)
	securityToken := d.Get("security_token").(string)
	appPrivateKeyData := d.Get("app_private_key_data").(string)
	caCertData := d.Get("ca_cert_data").(string)
	caCertName := d.Get("ca_cert_name").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.UpdateSalesforceTarget{
		Name:      name,
		AuthFlow:  authFlow,
		ClientId:  clientId,
		Email:     email,
		TenantUrl: tenantUrl,
		Token:     &token,
	}
	common.GetAkeylessPtr(&body.ClientSecret, clientSecret)
	common.GetAkeylessPtr(&body.Password, password)
	common.GetAkeylessPtr(&body.SecurityToken, securityToken)
	common.GetAkeylessPtr(&body.AppPrivateKeyData, appPrivateKeyData)
	common.GetAkeylessPtr(&body.CaCertData, caCertData)
	common.GetAkeylessPtr(&body.CaCertName, caCertName)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.UpdateSalesforceTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceSalesforceTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceSalesforceTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceSalesforceTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
