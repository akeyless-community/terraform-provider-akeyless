// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretAzure() *schema.Resource {
	return &schema.Resource{
		Description: "Azure AD dynamic secret resource",
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
				Optional:    true,
				Description: "Target name",
			},
			"azure_tenant_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure Tenant ID",
			},
			"azure_client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure Client ID",
			},
			"azure_client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Azure Client Secret",
			},
			"user_portal_access": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Azure User portal access",
				Default:     false,
			},
			"user_programmatic_access": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Azure User programmatic access",
				Default:     "true",
			},
			"app_obj_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure App Object Id",
			},
			"user_principal_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User Principal Name",
			},
			"user_group_obj_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User Group Object Id",
			},
			"user_role_template_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User Role Template Id",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"password_length": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The length of the password to be generated",
			},
			"encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Dynamic secret encryption key",
			},
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customize how temporary usernames are generated using go template",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access [true/false]",
			},
			"secure_access_web_browsing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Secure browser via Akeyless's Secure Remote Access (SRA)",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     "true",
				Description: "Enable Web Secure Remote Access",
			},
			"secure_access_url": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"azure_administrative_unit": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure AD administrative unit (relevant only when azure-user-portal-access=true)",
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
			"fixed_user_claim_keyname": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "FixedUserClaimKeyname",
			},
			"fixed_user_only": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Fixed user",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_web_proxy": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Web-Proxy via Akeyless's Secure Remote Access (SRA)",
			},
		},
	}
}

func resourceDynamicSecretAzureCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
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
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	azureAdministrativeUnit := d.Get("azure_administrative_unit").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	fixedUserClaimKeyname := d.Get("fixed_user_claim_keyname").(string)
	fixedUserOnly := d.Get("fixed_user_only").(bool)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)

	body := akeyless_api.DynamicSecretCreateAzure{
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
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.AzureAdministrativeUnit, azureAdministrativeUnit)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.FixedUserClaimKeyname, fixedUserClaimKeyname)
	common.GetAkeylessPtr(&body.FixedUserOnly, fixedUserOnly)
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	if len(itemCustomFields) > 0 {
		customFieldsMap := make(map[string]string)
		for k, v := range itemCustomFields {
			customFieldsMap[k] = v.(string)
		}
		body.ItemCustomFields = &customFieldsMap
	}

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
		err = d.Set("tags", rOut.Tags)
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
		err = common.SetDataByPrefixSlash(d, "encryption_key_name", *rOut.DynamicSecretKey, d.Get("encryption_key_name").(string))
		if err != nil {
			return err
		}
	}

	if rOut.UsernameTemplate != nil {
		err = d.Set("custom_username_template", *rOut.UsernameTemplate)
		if err != nil {
			return err
		}
	}

	if rOut.AzureAdministrativeUnit != nil {
		err = d.Set("azure_administrative_unit", *rOut.AzureAdministrativeUnit)
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
	if rOut.Metadata != nil {
		err = d.Set("description", *rOut.Metadata)
		if err != nil {
			return err
		}
	}
	if rOut.AzureFixedUserNameSubClaimKey != nil {
		err = d.Set("fixed_user_claim_keyname", *rOut.AzureFixedUserNameSubClaimKey)
		if err != nil {
			return err
		}
	}
	if rOut.AzureFixedUserOnly != nil {
		err = d.Set("fixed_user_only", *rOut.AzureFixedUserOnly)
		if err != nil {
			return err
		}
	}
	if rOut.ItemCustomFieldsDetails != nil && len(rOut.ItemCustomFieldsDetails) > 0 {
		customFields := make(map[string]string)
		for _, field := range rOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		if len(customFields) > 0 {
			err = d.Set("item_custom_fields", customFields)
			if err != nil {
				return err
			}
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceDynamicSecretAzureUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
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
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	azureAdministrativeUnit := d.Get("azure_administrative_unit").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	fixedUserClaimKeyname := d.Get("fixed_user_claim_keyname").(string)
	fixedUserOnly := d.Get("fixed_user_only").(bool)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)

	body := akeyless_api.DynamicSecretUpdateAzure{
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
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)
	common.GetAkeylessPtr(&body.AzureAdministrativeUnit, azureAdministrativeUnit)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.FixedUserClaimKeyname, fixedUserClaimKeyname)
	common.GetAkeylessPtr(&body.FixedUserOnly, fixedUserOnly)
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	if len(itemCustomFields) > 0 {
		customFieldsMap := make(map[string]string)
		for k, v := range itemCustomFields {
			customFieldsMap[k] = v.(string)
		}
		body.ItemCustomFields = &customFieldsMap
	}

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

	id := d.Id()

	err := resourceDynamicSecretAzureRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
