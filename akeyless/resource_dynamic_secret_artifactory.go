// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceDynamicSecretArtifactory() *schema.Resource {
	return &schema.Resource{
		Description: "Artifactory dynamic secret resource",
		Create:      resourceDynamicSecretArtifactoryCreate,
		Read:        resourceDynamicSecretArtifactoryRead,
		Update:      resourceDynamicSecretArtifactoryUpdate,
		Delete:      resourceDynamicSecretArtifactoryDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretArtifactoryImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("artifactory_admin_pwd"), cty.GetAttrPath("artifactory_admin_pwd_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic Secret name",
				ForceNew:    true,
			},
			"artifactory_token_scope": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Token scope provided as a space-separated list, for example: member-of-groups:readers",
			},
			"artifactory_token_audience": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A space-separate list of the other Artifactory instances or services that should accept this token., for example: jfrt@*",
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of existing target to use in dynamic secret creation",
			},
			"base_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Artifactory REST URL, must end with artifactory postfix",
			},
			"artifactory_admin_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Admin name",
			},
			"artifactory_admin_pwd": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Admin API Key/Password",
			},
			"artifactory_admin_pwd_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "artifactory_admin_pwd (write-only, not stored in state). Requires Terraform 1.11+. Bump artifactory_admin_pwd_wo_version to change it.",
			},
			"artifactory_admin_pwd_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for artifactory_admin_pwd_wo. Increment to update the value.",
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
				Computed:    true,
				Description: "Encrypt dynamic secret details with following key",
			},
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customize how temporary usernames are generated using go template",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Protection from accidental deletion of this item",
				Default:     false,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceDynamicSecretArtifactoryCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	artifactoryTokenScope := d.Get("artifactory_token_scope").(string)
	artifactoryTokenAudience := d.Get("artifactory_token_audience").(string)
	targetName := d.Get("target_name").(string)
	baseUrl := d.Get("base_url").(string)
	artifactoryAdminName := d.Get("artifactory_admin_name").(string)
	artifactoryAdminPwd, err := common.EffectiveSecretValue(d, "artifactory_admin_pwd", "artifactory_admin_pwd_wo")
	if err != nil {
		return err
	}
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	deleteProtection := d.Get("delete_protection").(bool)
	description := d.Get("description").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}

	body := akeyless_api.DynamicSecretCreateArtifactory{
		Name:                     name,
		ArtifactoryTokenScope:    artifactoryTokenScope,
		ArtifactoryTokenAudience: artifactoryTokenAudience,
		Token:                    &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.BaseUrl, baseUrl)
	common.GetAkeylessPtr(&body.ArtifactoryAdminName, artifactoryAdminName)
	common.GetAkeylessPtr(&body.ArtifactoryAdminPwd, artifactoryAdminPwd)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.Tags, tags)
	if deleteProtection {
		common.GetAkeylessPtr(&body.DeleteProtection, "true")
	}
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		body.ItemCustomFields = &itemCustomFields
	}

	_, resp, err := client.DynamicSecretCreateArtifactory(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretArtifactoryRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.ArtifactoryTokenScope != nil {
		err = d.Set("artifactory_token_scope", *rOut.ArtifactoryTokenScope)
		if err != nil {
			return err
		}
	}
	if rOut.ArtifactoryTokenAudience != nil {
		err = d.Set("artifactory_token_audience", *rOut.ArtifactoryTokenAudience)
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
	if rOut.ArtifactoryBaseUrl != nil {
		err = d.Set("base_url", *rOut.ArtifactoryBaseUrl)
		if err != nil {
			return err
		}
	}
	if rOut.ArtifactoryAdminUsername != nil {
		err = d.Set("artifactory_admin_name", *rOut.ArtifactoryAdminUsername)
		if err != nil {
			return err
		}
	}
	if rOut.ArtifactoryAdminApikey != nil {
		err = common.SetSecretFromRead(d, "artifactory_admin_pwd", "artifactory_admin_pwd_wo", "artifactory_admin_pwd_wo_version", *rOut.ArtifactoryAdminApikey)
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

	deleteProtectionVal := false
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = *rOut.DeleteProtection
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

func resourceDynamicSecretArtifactoryUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	artifactoryTokenScope := d.Get("artifactory_token_scope").(string)
	artifactoryTokenAudience := d.Get("artifactory_token_audience").(string)
	targetName := d.Get("target_name").(string)
	baseUrl := d.Get("base_url").(string)
	artifactoryAdminName := d.Get("artifactory_admin_name").(string)
	artifactoryAdminPwd, err := common.EffectiveSecretValue(d, "artifactory_admin_pwd", "artifactory_admin_pwd_wo")
	if err != nil {
		return err
	}
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	deleteProtection := d.Get("delete_protection").(bool)
	description := d.Get("description").(string)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}

	body := akeyless_api.DynamicSecretUpdateArtifactory{
		Name:                     name,
		ArtifactoryTokenScope:    artifactoryTokenScope,
		ArtifactoryTokenAudience: artifactoryTokenAudience,
		Token:                    &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.BaseUrl, baseUrl)
	common.GetAkeylessPtr(&body.ArtifactoryAdminName, artifactoryAdminName)
	common.GetAkeylessPtr(&body.ArtifactoryAdminPwd, artifactoryAdminPwd)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.Tags, tags)
	if deleteProtection {
		common.GetAkeylessPtr(&body.DeleteProtection, "true")
	}
	common.GetAkeylessPtr(&body.Description, description)
	if len(itemCustomFields) > 0 {
		body.ItemCustomFields = &itemCustomFields
	}

	_, resp, err := client.DynamicSecretUpdateArtifactory(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretArtifactoryDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretArtifactoryImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretArtifactoryRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
