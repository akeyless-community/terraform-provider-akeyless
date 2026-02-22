package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceFolder() *schema.Resource {
	return &schema.Resource{
		Description: "Folder Resource",
		Create:      resourceFolderCreate,
		Read:        resourceFolderRead,
		Update:      resourceFolderUpdate,
		Delete:      resourceFolderDelete,
		Importer: &schema.ResourceImporter{
			State: resourceFolderImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				Description:      "The name to the folder",
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of tags attached to this folder",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true, // if not provided on update - keep the existing value
				Description: "Protection from accidental deletion of this folder [true/false]",
			},
			"folder_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The ID of the folder",
			},
		},
	}
}

func resourceFolderCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Get("name").(string)
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tags := d.Get("tags").(*schema.Set)
	tagsList := common.ExpandStringList(tags.List())

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	body := akeyless_api.FolderCreate{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tagsList)

	rOut, _, err := client.FolderCreate(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Folder: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Folder: %v", err)
	}

	if rOut.FolderId != nil {
		err = d.Set("folder_id", int(*rOut.FolderId))
		if err != nil {
			return err
		}
	}

	d.SetId(name)

	return nil
}

func resourceFolderRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Id()

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	body := akeyless_api.FolderGet{
		Name:  name,
		Token: &token,
	}

	rOut, res, err := client.FolderGet(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res != nil && res.StatusCode == http.StatusNotFound {
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't get Folder: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get Folder: %v", err)
	}

	if rOut.Folder == nil {
		d.SetId("")
		return nil
	}

	folder := rOut.Folder

	if folder.FolderId != nil {
		err = d.Set("folder_id", int(*folder.FolderId))
		if err != nil {
			return err
		}
	}
	if folder.Metadata != nil {
		err = d.Set("description", *folder.Metadata)
		if err != nil {
			return err
		}
	}
	if folder.Tags != nil {
		err = d.Set("tags", folder.Tags)
		if err != nil {
			return err
		}
	}
	if folder.DeleteProtection != nil {
		err := d.Set("delete_protection", strconv.FormatBool(*folder.DeleteProtection))
		if err != nil {
			return err
		}
	}

	d.SetId(name)

	return nil
}

func resourceFolderUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Get("name").(string)
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(string)

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	body := akeyless_api.FolderUpdate{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	if d.HasChange("tags") {
		oldRaw, newRaw := d.GetChange("tags")
		oldTags := common.ExpandStringList(oldRaw.(*schema.Set).List())
		newTags := common.ExpandStringList(newRaw.(*schema.Set).List())

		addTags, removeTags := diffTags(oldTags, newTags)

		if len(addTags) > 0 {
			common.GetAkeylessPtr(&body.AddTag, addTags)
		}
		if len(removeTags) > 0 {
			common.GetAkeylessPtr(&body.RmTag, removeTags)
		}
	}

	_, _, err := client.FolderUpdate(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update Folder: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update Folder: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceFolderDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Id()

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	body := akeyless_api.FolderDelete{
		Name:  name,
		Token: &token,
	}

	_, res, err := client.FolderDelete(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res != nil && res.StatusCode == http.StatusNotFound {
				return nil
			}
			return fmt.Errorf("can't delete Folder: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't delete Folder: %v", err)
	}

	return nil
}

func resourceFolderImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()

	err := resourceFolderRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func diffTags(oldTags, newTags []string) (add, remove []string) {
	oldSet := make(map[string]struct{}, len(oldTags))
	for _, t := range oldTags {
		oldSet[t] = struct{}{}
	}

	newSet := make(map[string]struct{}, len(newTags))
	for _, t := range newTags {
		newSet[t] = struct{}{}
	}

	for _, t := range newTags {
		if _, ok := oldSet[t]; !ok {
			add = append(add, t)
		}
	}

	for _, t := range oldTags {
		if _, ok := newSet[t]; !ok {
			remove = append(remove, t)
		}
	}

	return add, remove
}
