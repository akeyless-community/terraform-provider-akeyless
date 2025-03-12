package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceStaticSecret() *schema.Resource {
	return &schema.Resource{
		Description: "Static secret Resource",
		Create:      resourceStaticSecretCreate,
		Read:        resourceStaticSecretRead,
		Update:      resourceStaticSecretUpdate,
		Delete:      resourceStaticSecretDelete,
		Importer: &schema.ResourceImporter{
			State: resourceStaticSecretImport,
		},
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path where the secret will be stored.",
			},
			"type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Secret type [generic/password]",
				Default:     "generic",
			},
			"value": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "The secret content.",
			},
			"format": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Secret format [text/json/key-value] (relevant only for type 'generic')",
				Default:     "text",
			},
			"multiline_value": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "The provided value is a multiline value (separated by '\n')",
			},
			"inject_url": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of URLs associated with the item (relevant only for type 'password')",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Password value (relevant only for type 'password')",
			},
			"username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Username value (relevant only for type 'password')",
			},
			"custom_field": {
				Type:        schema.TypeMap,
				Optional:    true,
				Sensitive:   true,
				Description: "Additional custom fields to associate with the item (e.g fieldName1=value1) (relevant only for type 'password')",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"version": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The version of the secret.",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
			"protection_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that is used to encrypt the secret value (if empty, the account default protectionKey key will be used)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_ssh_creds": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Static-Secret values contains SSH Credentials, either Private Key or Password [password/private-key]",
			},
			"secure_access_url": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Destination URL to inject secrets.",
			},
			"secure_access_web_browsing": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Secure browser via Akeyless's Secure Remote Access (SRA)",
			},
			"secure_access_bastion_issuer": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Secure Access",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "Target servers for connections., For multiple values repeat this flag.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_ssh_user": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Override the SSH username as indicated in SSH Certificate Issuer",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable Web Secure Remote Access ",
				Computed:    true,
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Protect secret from deletion",
			},
		},
	}
}

func resourceStaticSecretCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)
	secretType := d.Get("type").(string)
	value := d.Get("value").(string)
	format := d.Get("format").(string)
	injectUrlSet := d.Get("inject_url").(*schema.Set)
	injectUrl := common.ExpandStringList(injectUrlSet.List())
	password := d.Get("password").(string)
	username := d.Get("username").(string)
	customField := d.Get("custom_field").(map[string]interface{})
	ProtectionKey := d.Get("protection_key").(string)
	multilineValue := d.Get("multiline_value").(bool)
	description := d.Get("description").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessSshCreds := d.Get("secure_access_ssh_creds").(string)
	secureAccessUrl := d.Get("secure_access_url").(string)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessSshUser := d.Get("secure_access_ssh_user").(string)
	deleteProtection := d.Get("delete_protection").(string)

	tags := d.Get("tags").(*schema.Set)
	tagsList := common.ExpandStringList(tags.List())

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	body := akeyless_api.CreateSecret{
		Name:           path,
		Type:           &secretType,
		Value:          value,
		MultilineValue: akeyless_api.PtrBool(multilineValue),
		Token:          &token,
	}
	if ProtectionKey != "" {
		body.ProtectionKey = akeyless_api.PtrString(ProtectionKey)
	}
	common.GetAkeylessPtr(&body.Tags, tagsList)

	common.GetAkeylessPtr(&body.Format, format)
	common.GetAkeylessPtr(&body.InjectUrl, injectUrl)
	common.GetAkeylessPtr(&body.Password, password)
	common.GetAkeylessPtr(&body.Username, username)
	common.GetAkeylessPtr(&body.CustomField, customField)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessSshCreds, secureAccessSshCreds)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessSshUser, secureAccessSshUser)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.CreateSecret(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	item := akeyless_api.DescribeItem{
		Name:         path,
		ShowVersions: akeyless_api.PtrBool(true),
		Token:        &token,
	}

	itemOut, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return err
	}

	version := itemOut.LastVersion

	err = d.Set("version", *version)
	if err != nil {
		return err
	}

	pk := itemOut.ProtectionKeyName
	err = d.Set("protection_key", *pk)
	if err != nil {
		return err
	}

	d.SetId(path)

	return nil
}

func resourceStaticSecretRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	gsvBody := akeyless_api.GetSecretValue{
		Names: []string{path},
		Token: &token,
	}

	gsvOut, res, err := client.GetSecretValue(ctx).Body(gsvBody).Execute()

	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The secret was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't get Secret value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get Secret value: %v", err)
	}

	item := akeyless_api.DescribeItem{
		Name:         path,
		ShowVersions: akeyless_api.PtrBool(true),
		Token:        &token,
	}

	itemOut, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return err
	}

	secretType := itemOut.ItemSubType
	err = d.Set("type", *secretType)
	if err != nil {
		return err
	}

	version := itemOut.LastVersion
	err = d.Set("version", *version)
	if err != nil {
		return err
	}

	pk := itemOut.ProtectionKeyName
	err = d.Set("protection_key", *pk)
	if err != nil {
		return err
	}

	if itemOut.ItemMetadata != nil {
		err := d.Set("description", *itemOut.ItemMetadata)
		if err != nil {
			return err
		}
	}
	if itemOut.ItemTags != nil {
		err = d.Set("tags", *itemOut.ItemTags)
		if err != nil {
			return err
		}
	}
	if itemOut.DeleteProtection != nil {
		err := d.Set("delete_protection", *itemOut.DeleteProtection)
		if err != nil {
			return err
		}
	}

	info := itemOut.ItemGeneralInfo
	if info != nil {
		staticSecretInfo := info.StaticSecretInfo
		if staticSecretInfo != nil {
			if staticSecretInfo.Format != nil && d.Get("format") != "" {
				err := d.Set("format", *staticSecretInfo.Format)
				if err != nil {
					return err
				}
			}
			if staticSecretInfo.Websites != nil {
				err := d.Set("inject_url", *staticSecretInfo.Websites)
				if err != nil {
					return err
				}
			}
		}
	}

	value := gsvOut[path]

	stringValue, ok := value.(string)
	if !ok {
		return fmt.Errorf("wrong value variable string type")
	}

	if *secretType == "generic" {
		err = d.Set("value", stringValue)
		if err != nil {
			return err
		}
	} else {
		var jsonValue map[string]interface{}
		err = json.Unmarshal([]byte(stringValue), &jsonValue)
		if err != nil {
			return fmt.Errorf("can't convert secret password value")
		}
		err = d.Set("password", jsonValue["password"])
		if err != nil {
			return err
		}
		err = d.Set("username", jsonValue["username"])
		if err != nil {
			return err
		}
		delete(jsonValue, "username")
		delete(jsonValue, "password")
		err = d.Set("custom_field", jsonValue)
		if err != nil {
			return err
		}
	}

	common.GetSraFromItem(d, itemOut)

	return nil
}

func resourceStaticSecretUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Get("path").(string)

	if !d.HasChangeExcept("keep_prev_version") {
		return nil
	}

	if d.HasChanges("value", "multiline_value", "protection_key", "format", "inject_url", "password", "username", "custom_field") {
		value := d.Get("value").(string)
		format := d.Get("format").(string)
		protectionKey := d.Get("protection_key").(string)
		multilineValue := d.Get("multiline_value").(bool)
		keepPrevVersion := d.Get("keep_prev_version").(string)
		injectUrlSet := d.Get("inject_url").(*schema.Set)
		injectUrl := common.ExpandStringList(injectUrlSet.List())
		username := d.Get("username").(string)
		password := d.Get("password").(string)
		customField := d.Get("custom_field").(map[string]interface{})

		body := akeyless_api.UpdateSecretVal{
			Name:      path,
			Key:       akeyless_api.PtrString(protectionKey),
			Value:     value,
			Multiline: akeyless_api.PtrBool(multilineValue),
			Token:     &token,
		}

		common.GetAkeylessPtr(&body.Format, format)
		common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)
		common.GetAkeylessPtr(&body.InjectUrl, injectUrl)
		common.GetAkeylessPtr(&body.Username, username)
		common.GetAkeylessPtr(&body.Password, password)
		if len(customField) > 0 {
			common.GetAkeylessPtr(&body.CustomField, customField)
		}

		_, _, err := client.UpdateSecretVal(ctx).Body(body).Execute()
		if err != nil {
			if errors.As(err, &apiErr) {
				return fmt.Errorf("can't update Secret: %v", string(apiErr.Body()))
			}
			return fmt.Errorf("can't update Secret: %v", err)
		}
	}

	tags := d.Get("tags").(*schema.Set)
	tagsList := common.ExpandStringList(tags.List())
	description := d.Get("description").(string)

	secureAccessHost := d.Get("secure_access_host").(*schema.Set)
	secureAccessHostList := common.ExpandStringList(secureAccessHost.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessSshCreds := d.Get("secure_access_ssh_creds").(string)
	secureAccessUrl := d.Get("secure_access_url").(string)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessSshUser := d.Get("secure_access_ssh_user").(string)

	bodyItem := akeyless_api.UpdateItem{
		Name:    path,
		NewName: akeyless_api.PtrString(path),
		Token:   &token,
	}

	add, remove, err := common.GetTagsForUpdate(d, path, token, tagsList, client)
	if err == nil {
		if len(add) > 0 {
			common.GetAkeylessPtr(&bodyItem.AddTag, add)
		}
		if len(remove) > 0 {
			common.GetAkeylessPtr(&bodyItem.RmTag, remove)
		}
	}

	common.GetAkeylessPtr(&bodyItem.Description, description)
	common.GetAkeylessPtr(&bodyItem.SecureAccessHost, secureAccessHostList)
	common.GetAkeylessPtr(&bodyItem.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&bodyItem.SecureAccessSshCreds, secureAccessSshCreds)
	common.GetAkeylessPtr(&bodyItem.SecureAccessUrl, secureAccessUrl)
	common.GetAkeylessPtr(&bodyItem.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&bodyItem.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&bodyItem.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&bodyItem.SecureAccessSshCredsUser, secureAccessSshUser)

	_, _, err = client.UpdateItem(ctx).Body(bodyItem).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update item: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update item: %v", err)
	}

	item := akeyless_api.DescribeItem{
		Name:         path,
		ShowVersions: akeyless_api.PtrBool(false),
		Token:        &token,
	}

	itemOut, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return err
	}

	version := itemOut.LastVersion

	err = d.Set("version", *version)
	if err != nil {
		return err
	}

	pk := itemOut.ProtectionKeyName
	err = d.Set("protection_key", *pk)
	if err != nil {
		return err
	}

	d.SetId(path)

	return nil
}

func resourceStaticSecretDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()

	path := d.Id()

	deleteItem := akeyless_api.DeleteItem{
		Token: &token,
		Name:  path,
	}

	_, _, err := client.DeleteItem(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceStaticSecretImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceStaticSecretRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("path", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
