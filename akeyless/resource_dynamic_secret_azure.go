// generated fule
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

func resourceDynamicSecretAzure() *schema.Resource {
	return &schema.Resource{
		Description: "Azure AD producer resource",
		Create:      resourceDynamicSecretAzureCreate,
		Read:        resourceDynamicSecretAzureRead,
		Update:      resourceDynamicSecretAzureUpdate,
		Delete:      resourceDynamicSecretAzureDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretAzureImport,
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
				Required:    false,
				Optional:    true,
				Description: "Name of existing target to use in producer creation",
			},
			"azure_tenant_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Azure Tenant ID",
			},
			"azure_client_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Azure Client ID (Application ID)",
			},
			"azure_client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Azure AD Client Secret",
			},
			"user_portal_access": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable Azure AD user portal access",
				Default:     "false",
			},
			"user_programmatic_access": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable Azure AD user programmatic access",
				Default:     "true",
			},
			"app_obj_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Azure App Object ID (required if selected programmatic access)",
			},
			"user_principal_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Azure AD User Principal Name (required if selected Portal access)",
			},
			"user_group_obj_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Azure AD User Group Object ID (required if selected Portal access)",
			},
			"user_role_template_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Azure AD User Role Template ID (required if selected Portal access)",
			},
			"producer_encryption_key_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Encrypt producer with following key",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"tags": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: --tag Tag1 --tag Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_web_browsing": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Secure browser via Akeyless Web Access Bastion",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable Web Secure Remote Access ",
				Default:     "true",
			},
			"secure_access_url": {
				Type:     schema.TypeString,
				Required: false,
				Optional: true,
				Computed: true,
			},
		},
	}
}

func resourceDynamicSecretAzureCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	azureTenantId := d.Get("azure_tenant_id").(string)
	azureClientId := d.Get("azure_client_id").(string)
	azureClientSecret := d.Get("azure_client_secret").(string)
	userPortalAccess := d.Get("user_portal_access").(bool)
	userProgrammaticAccess := d.Get("user_programmatic_access").(bool)
	appObjId := d.Get("app_obj_id").(string)
	userPrincipalName := d.Get("user_principal_name").(string)
	userGroupObjId := d.Get("user_group_obj_id").(string)
	userRoleTemplateId := d.Get("user_role_template_id").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.DynamicSecretCreateAzure{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.AzureTenantId, azureTenantId)
	common.GetAkeylessPtr(&body.AzureClientId, azureClientId)
	common.GetAkeylessPtr(&body.AzureClientSecret, azureClientSecret)
	common.GetAkeylessPtr(&body.UserPortalAccess, userPortalAccess)
	common.GetAkeylessPtr(&body.UserProgrammaticAccess, userProgrammaticAccess)
	common.GetAkeylessPtr(&body.AppObjId, appObjId)
	common.GetAkeylessPtr(&body.UserPrincipalName, userPrincipalName)
	common.GetAkeylessPtr(&body.UserGroupObjId, userGroupObjId)
	common.GetAkeylessPtr(&body.UserRoleTemplateId, userRoleTemplateId)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.DynamicSecretCreateAzure(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretAzureRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.AzureTenantId != nil {
		err = d.Set("azure_tenant_id", *rOut.AzureTenantId)
		if err != nil {
			return err
		}
	}
	if rOut.AzureClientId != nil {
		err = d.Set("azure_client_id", *rOut.AzureClientId)
		if err != nil {
			return err
		}
	}
	if rOut.AzureClientSecret != nil {
		err = d.Set("azure_client_secret", *rOut.AzureClientSecret)
		if err != nil {
			return err
		}
	}
	if rOut.UserPrincipalName != nil {
		err = d.Set("user_principal_name", *rOut.UserPrincipalName)
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

	if rOut.AzureUserPortalAccess != nil {
		err = d.Set("user_portal_access", *rOut.AzureUserPortalAccess)
		if err != nil {
			return err
		}
	}
	if rOut.AzureUserProgrammaticAccess != nil {
		err = d.Set("user_programmatic_access", *rOut.AzureUserProgrammaticAccess)
		if err != nil {
			return err
		}
	}
	if rOut.AzureAppObjectId != nil {
		err = d.Set("app_obj_id", *rOut.AzureAppObjectId)
		if err != nil {
			return err
		}
	}
	if rOut.AzureUserGroupsObjId != nil {
		err = d.Set("user_group_obj_id", *rOut.AzureUserGroupsObjId)
		if err != nil {
			return err
		}
	}
	if rOut.AzureUserRolesTemplateId != nil {
		err = d.Set("user_role_template_id", *rOut.AzureUserRolesTemplateId)
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

func resourceDynamicSecretAzureUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	azureTenantId := d.Get("azure_tenant_id").(string)
	azureClientId := d.Get("azure_client_id").(string)
	azureClientSecret := d.Get("azure_client_secret").(string)
	userPortalAccess := d.Get("user_portal_access").(bool)
	userProgrammaticAccess := d.Get("user_programmatic_access").(bool)
	appObjId := d.Get("app_obj_id").(string)
	userPrincipalName := d.Get("user_principal_name").(string)
	userGroupObjId := d.Get("user_group_obj_id").(string)
	userRoleTemplateId := d.Get("user_role_template_id").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.DynamicSecretUpdateAzure{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.AzureTenantId, azureTenantId)
	common.GetAkeylessPtr(&body.AzureClientId, azureClientId)
	common.GetAkeylessPtr(&body.AzureClientSecret, azureClientSecret)
	common.GetAkeylessPtr(&body.UserPortalAccess, userPortalAccess)
	common.GetAkeylessPtr(&body.UserProgrammaticAccess, userProgrammaticAccess)
	common.GetAkeylessPtr(&body.AppObjId, appObjId)
	common.GetAkeylessPtr(&body.UserPrincipalName, userPrincipalName)
	common.GetAkeylessPtr(&body.UserGroupObjId, userGroupObjId)
	common.GetAkeylessPtr(&body.UserRoleTemplateId, userRoleTemplateId)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.DynamicSecretUpdateAzure(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretAzureDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretAzureImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	return resourceDynamicSecretImport(d, m)
}
