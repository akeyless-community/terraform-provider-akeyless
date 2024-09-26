package akeyless

import (
	"context"
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
			"value": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Sensitive:   true,
				Description: "The secret content.",
			},
			"format": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Secret format [text/json] (relevant only for type 'generic')",
			},
			"multiline_value": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "The provided value is a multiline value (separated by '\n')",
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
				Required:    false,
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
				Description: "Secure browser via Akeyless Web Access Bastion",
			},
			"secure_access_bastion_issuer": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Bastion",
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
		},
	}
}

func resourceStaticSecretCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)
	value := d.Get("value").(string)
	format := d.Get("format").(string)
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

	tags := d.Get("tags").(*schema.Set)
	tagsList := common.ExpandStringList(tags.List())

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	body := akeyless_api.CreateSecret{
		Name:           path,
		Value:          value,
		MultilineValue: akeyless_api.PtrBool(multilineValue),
		Token:          &token,
	}
	if ProtectionKey != "" {
		body.ProtectionKey = akeyless_api.PtrString(ProtectionKey)
	}
	common.GetAkeylessPtr(&body.Tags, tagsList)

	common.GetAkeylessPtr(&body.Format, format)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessSshCreds, secureAccessSshCreds)
	common.GetAkeylessPtr(&body.SecureAccessUrl, secureAccessUrl)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessSshUser, secureAccessSshUser)

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
		}
	}

	err = d.Set("value", gsvOut[path])
	if err != nil {
		return err
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

	if d.HasChanges("value", "multiline_value", "protection_key", "format") {
		value := d.Get("value").(string)
		format := d.Get("format").(string)
		protectionKey := d.Get("protection_key").(string)
		multilineValue := d.Get("multiline_value").(bool)
		keepPrevVersion := d.Get("keep_prev_version").(string)

		body := akeyless_api.UpdateSecretVal{
			Name:      path,
			Key:       akeyless_api.PtrString(protectionKey),
			Value:     value,
			Multiline: akeyless_api.PtrBool(multilineValue),
			Token:     &token,
		}

		common.GetAkeylessPtr(&body.Format, format)
		common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

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

	path := d.Id()

	deleteItem := akeyless_api.DeleteItem{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
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
