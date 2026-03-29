package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretChef() *schema.Resource {
	return &schema.Resource{
		Description: "Chef dynamic secret resource",
		Create:      resourceDynamicSecretChefCreate,
		Read:        resourceDynamicSecretChefRead,
		Update:      resourceDynamicSecretChefUpdate,
		Delete:      resourceDynamicSecretChefDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretChefImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
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
			"chef_orgs": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Organizations",
			},
			"chef_server_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Server key",
			},
			"chef_server_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Server URL",
			},
			"chef_server_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Server username",
			},
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customize how temporary usernames are generated using go template",
			},
			"password_length": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The length of the password to be generated",
			},
			"skip_ssl": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Skip SSL",
				Default:     true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Target name",
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
				Description: "Dynamic producer encryption key",
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

func resourceDynamicSecretChefCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	chefOrgs := d.Get("chef_orgs").(string)
	chefServerKey := d.Get("chef_server_key").(string)
	chefServerUrl := d.Get("chef_server_url").(string)
	chefServerUsername := d.Get("chef_server_username").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	passwordLength := d.Get("password_length").(string)
	skipSsl := d.Get("skip_ssl").(bool)
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.GatewayCreateProducerChef{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ChefOrgs, chefOrgs)
	common.GetAkeylessPtr(&body.ChefServerKey, chefServerKey)
	common.GetAkeylessPtr(&body.ChefServerUrl, chefServerUrl)
	common.GetAkeylessPtr(&body.ChefServerUsername, chefServerUsername)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.SkipSsl, skipSsl)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.GatewayCreateProducerChef(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretChefRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.ChefServerUrl != nil {
		err = d.Set("chef_server_url", *rOut.ChefServerUrl)
		if err != nil {
			return err
		}
	}
	if rOut.ChefServerUsername != nil {
		err = d.Set("chef_server_username", *rOut.ChefServerUsername)
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

	d.SetId(path)

	return nil
}

func resourceDynamicSecretChefUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	chefOrgs := d.Get("chef_orgs").(string)
	chefServerKey := d.Get("chef_server_key").(string)
	chefServerUrl := d.Get("chef_server_url").(string)
	chefServerUsername := d.Get("chef_server_username").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	passwordLength := d.Get("password_length").(string)
	skipSsl := d.Get("skip_ssl").(bool)
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.GatewayUpdateProducerChef{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ChefOrgs, chefOrgs)
	common.GetAkeylessPtr(&body.ChefServerKey, chefServerKey)
	common.GetAkeylessPtr(&body.ChefServerUrl, chefServerUrl)
	common.GetAkeylessPtr(&body.ChefServerUsername, chefServerUsername)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.SkipSsl, skipSsl)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.GatewayUpdateProducerChef(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretChefDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretChefImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretChefRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
