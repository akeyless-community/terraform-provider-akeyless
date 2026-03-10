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

func resourcePasskey() *schema.Resource {
	return &schema.Resource{
		Description: "Passkey resource",
		Create:      resourcePasskeyCreate,
		Read:        resourcePasskeyRead,
		Update:      resourcePasskeyUpdate,
		Delete:      resourcePasskeyDelete,
		Importer: &schema.ResourceImporter{
			State: resourcePasskeyImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ClassicKey name",
				ForceNew:    true,
			},
			"alg": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Passkey type; options: [EC256, EC384, EC512]",
			},
			"accessibility": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "For personal password manager",
				Default:     "regular",
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
			"origin_url": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Originating websites for this passkey",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"protection_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "For Password Management use",
			},
		},
	}
}

func resourcePasskeyCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	alg := d.Get("alg").(string)
	accessibility := d.Get("accessibility").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	protectionKeyName := d.Get("protection_key_name").(string)
	username := d.Get("username").(string)

	body := akeyless_api.CreatePasskey{
		Name:  name,
		Alg:   alg,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Accessibility, accessibility)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.ProtectionKeyName, protectionKeyName)
	common.GetAkeylessPtr(&body.Username, username)

	if v, ok := d.GetOk("origin_url"); ok {
		originUrlList := v.([]interface{})
		originUrl := make([]string, len(originUrlList))
		for i, item := range originUrlList {
			originUrl[i] = item.(string)
		}
		body.OriginUrl = originUrl
	}

	if v, ok := d.GetOk("tags"); ok {
		tagsSet := v.(*schema.Set).List()
		tags := make([]string, len(tagsSet))
		for i, item := range tagsSet {
			tags[i] = item.(string)
		}
		body.Tags = tags
	}

	_, _, err := client.CreatePasskey(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Passkey: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Passkey: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourcePasskeyRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DescribeItem{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DescribeItem(ctx).Body(body).Execute()
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

	if rOut.ItemMetadata != nil {
		err = d.Set("description", *rOut.ItemMetadata)
		if err != nil {
			return err
		}
	}
	if rOut.ProtectionKeyName != nil {
		err = d.Set("protection_key_name", *rOut.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.ItemGeneralInfo != nil && rOut.ItemGeneralInfo.ClassicKeyDetails != nil && rOut.ItemGeneralInfo.ClassicKeyDetails.KeyType != nil {
		err = d.Set("alg", *rOut.ItemGeneralInfo.ClassicKeyDetails.KeyType)
		if err != nil {
			return err
		}
	}
	if rOut.ItemAccessibility != nil {
		accessibility := "regular"
		if *rOut.ItemAccessibility == 1 {
			accessibility = "personal"
		}
		err = d.Set("accessibility", accessibility)
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
	if rOut.ItemTags != nil {
		err = d.Set("tags", rOut.ItemTags)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourcePasskeyUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tagList := common.ExpandStringList(tagsSet.List())

	body := akeyless_api.UpdateItem{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	add, remove, err := common.GetTagsForUpdate(d, name, token, tagList, client)
	if err == nil {
		if len(add) > 0 {
			common.GetAkeylessPtr(&body.AddTag, add)
		}
		if len(remove) > 0 {
			common.GetAkeylessPtr(&body.RmTag, remove)
		}
	}

	_, _, err = client.UpdateItem(ctx).Body(body).Execute()
	if err != nil {
		var updateApiErr akeyless_api.GenericOpenAPIError
		if errors.As(err, &updateApiErr) {
			return fmt.Errorf("can't update Passkey: %v", string(updateApiErr.Body()))
		}
		return fmt.Errorf("can't update Passkey: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourcePasskeyDelete(d *schema.ResourceData, m interface{}) error {
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

func resourcePasskeyImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourcePasskeyRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
