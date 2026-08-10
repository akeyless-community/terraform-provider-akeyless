// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceDynamicSecretGoogleWorkspace() *schema.Resource {
	return &schema.Resource{
		Description: "Google Workspace dynamic secret resource",
		Create:      resourceDynamicSecretGoogleWorkspaceCreate,
		Read:        resourceDynamicSecretGoogleWorkspaceRead,
		Update:      resourceDynamicSecretGoogleWorkspaceUpdate,
		Delete:      resourceDynamicSecretGoogleWorkspaceDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretGoogleWorkspaceImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("gcp_key"), cty.GetAttrPath("gcp_key_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
			},
			"access_mode": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Adding a user to an existing group or assign an admin role to a user [group/role]",
			},
			"admin_email": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Admin user email",
			},
			"gcp_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Base64-encoded service account private key text",
			},
			"gcp_key_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"gcp_key_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "Base64-encoded service account private key text (write-only, not stored in state). Requires Terraform 1.11+. Bump gcp_key_wo_version to change it.",
			},
			"gcp_key_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"gcp_key_wo"},
				Description:  "Version trigger for gcp_key_wo. Increment to update the password.",
			},
			"group_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A group email, relevant only for group access-mode",
			},
			"group_role": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Group role [OWNER/MANAGER/MEMBER], relevant only for group access-mode",
			},
			"role_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of the admin role to assign to the user, relevant only for role access-mode",
			},
			"role_scope": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The scope in which this role is assigned [CUSTOMER/ORG_UNIT], relevant only for role access-mode",
				Default:     "CUSTOMER",
			},
			"fixed_user_claim_keyname": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "ext_email",
				Description: "For externally provided users, denotes the key-name of IdP claim to extract the username from",
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of existing target to use in dynamic secret creation",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"producer_encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Dynamic producer encryption key",
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
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access [true/false]",
			},
			"secure_access_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Destination URL to inject secrets",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable Web Secure Remote Access",
			},
			"secure_access_web_browsing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Secure browser via Akeyless's Secure Remote Access (SRA)",
			},
			"secure_access_web_proxy": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Web-Proxy via Akeyless's Secure Remote Access (SRA)",
			},
		},
	}
}

func resourceDynamicSecretGoogleWorkspaceCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	accessMode := d.Get("access_mode").(string)
	adminEmail := d.Get("admin_email").(string)
	gcpKey, err := common.EffectiveSecretValue(d, "gcp_key", "gcp_key_wo")
	if err != nil {
		return err
	}
	groupEmail := d.Get("group_email").(string)
	groupRole := d.Get("group_role").(string)
	roleName := d.Get("role_name").(string)
	roleScope := d.Get("role_scope").(string)
	fixedUserClaimKeyname := d.Get("fixed_user_claim_keyname").(string)
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessUrl := d.Get("secure_access_url").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)

	body := akeyless_api.DynamicSecretCreateGoogleWorkspace{
		Name:       name,
		AccessMode: accessMode,
		AdminEmail: adminEmail,
		Token:      &token,
	}
	common.GetAkeylessPtr(&body.GcpKey, gcpKey)
	common.GetAkeylessPtr(&body.GroupEmail, groupEmail)
	common.GetAkeylessPtr(&body.GroupRole, groupRole)
	common.GetAkeylessPtr(&body.RoleName, roleName)
	common.GetAkeylessPtr(&body.RoleScope, roleScope)
	common.GetAkeylessPtr(&body.FixedUserClaimKeyname, fixedUserClaimKeyname)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)
	if d.Get("secure_access_web") != nil {
		body.SecureAccessWeb = &secureAccessWeb
	}
	if d.Get("secure_access_web_browsing") != nil {
		body.SecureAccessWebBrowsing = &secureAccessWebBrowsing
	}
	if d.Get("secure_access_web_proxy") != nil {
		body.SecureAccessWebProxy = &secureAccessWebProxy
	}
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.DynamicSecretCreateGoogleWorkspace(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretGoogleWorkspaceRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get dynamic secret value", res, err)
	}

	if rOut.GoogleWorkspaceAccessMode != nil {
		err = d.Set("access_mode", *rOut.GoogleWorkspaceAccessMode)
		if err != nil {
			return err
		}
	}
	if rOut.GoogleWorkspaceAdminName != nil {
		err = d.Set("admin_email", *rOut.GoogleWorkspaceAdminName)
		if err != nil {
			return err
		}
	}
	if rOut.GoogleWorkspaceGroupName != nil {
		err = d.Set("group_email", *rOut.GoogleWorkspaceGroupName)
		if err != nil {
			return err
		}
	}
	if rOut.GoogleWorkspaceGroupRole != nil {
		err = d.Set("group_role", *rOut.GoogleWorkspaceGroupRole)
		if err != nil {
			return err
		}
	}
	if rOut.GoogleWorkspaceRoleName != nil {
		err = d.Set("role_name", *rOut.GoogleWorkspaceRoleName)
		if err != nil {
			return err
		}
	}
	if rOut.GoogleWorkspaceRoleScope != nil {
		err = d.Set("role_scope", *rOut.GoogleWorkspaceRoleScope)
		if err != nil {
			return err
		}
	}
	if rOut.GoogleWorkspaceFixedUserNameSubClaimKey != nil {
		err = d.Set("fixed_user_claim_keyname", *rOut.GoogleWorkspaceFixedUserNameSubClaimKey)
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
	if rOut.UserTtl != nil {
		err = d.Set("user_ttl", *rOut.UserTtl)
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
	if rOut.Tags != nil {
		err = d.Set("tags", rOut.Tags)
		if err != nil {
			return err
		}
	}
	if len(rOut.ItemCustomFieldsDetails) > 0 {
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

	d.SetId(path)

	return nil
}

func resourceDynamicSecretGoogleWorkspaceUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	accessMode := d.Get("access_mode").(string)
	adminEmail := d.Get("admin_email").(string)
	gcpKey, err := common.SecretValueForUpdate(d, "gcp_key", "gcp_key_wo")
	if err != nil {
		return err
	}
	groupEmail := d.Get("group_email").(string)
	groupRole := d.Get("group_role").(string)
	roleName := d.Get("role_name").(string)
	roleScope := d.Get("role_scope").(string)
	fixedUserClaimKeyname := d.Get("fixed_user_claim_keyname").(string)
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessUrl := d.Get("secure_access_url").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)

	body := akeyless_api.DynamicSecretUpdateGoogleWorkspace{
		Name:       name,
		AccessMode: accessMode,
		AdminEmail: adminEmail,
		Token:      &token,
	}
	common.SetOptionalString(&body.GcpKey, gcpKey)
	common.GetAkeylessPtr(&body.GroupEmail, groupEmail)
	common.GetAkeylessPtr(&body.GroupRole, groupRole)
	common.GetAkeylessPtr(&body.RoleName, roleName)
	common.GetAkeylessPtr(&body.RoleScope, roleScope)
	common.GetAkeylessPtr(&body.FixedUserClaimKeyname, fixedUserClaimKeyname)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)
	if d.Get("secure_access_web") != nil {
		body.SecureAccessWeb = &secureAccessWeb
	}
	if d.Get("secure_access_web_browsing") != nil {
		body.SecureAccessWebBrowsing = &secureAccessWebBrowsing
	}
	if d.Get("secure_access_web_proxy") != nil {
		body.SecureAccessWebProxy = &secureAccessWebProxy
	}
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.DynamicSecretUpdateGoogleWorkspace(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretGoogleWorkspaceDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretGoogleWorkspaceImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretGoogleWorkspaceRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
