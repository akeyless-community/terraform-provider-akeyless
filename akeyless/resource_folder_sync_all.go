package akeyless

import (
	"context"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceFolderSyncAll() *schema.Resource {
	return &schema.Resource{
		Description: "Folder sync all resource",
		Create:      resourceFolderSyncAllCreate,
		Read:        resourceFolderSyncAllRead,
		Delete:      resourceFolderSyncAllDelete,
		Importer: &schema.ResourceImporter{
			State: resourceFolderSyncAllImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Folder name",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The ID of this resource.",
			},
		},
	}
}

func resourceFolderSyncAllCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	folderName := d.Get("name").(string)

	body := akeyless_api.NewFolderSyncAll(folderName)
	body.Token = &token

	_, resp, err := client.FolderSyncAll(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't sync folder", resp, err)
	}

	d.SetId(buildFolderSyncAllID(folderName))
	return resourceFolderSyncAllRead(d, m)
}

func resourceFolderSyncAllRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	folderName := d.Id()

	body := akeyless_api.FolderGet{
		Name:  folderName,
		Token: &token,
	}

	rOut, res, err := client.FolderGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get folder", res, err)
	}
	if rOut.Folder == nil {
		d.SetId("")
		return nil
	}

	d.SetId(buildFolderSyncAllID(folderName))
	return nil
}

func resourceFolderSyncAllDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	folderName := d.Id()

	body := akeyless_api.NewFolderDeleteSync(folderName, "")
	body.Token = &token

	_, _, err := client.FolderDeleteSync(ctx).Body(*body).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceFolderSyncAllImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()

	err := resourceFolderSyncAllRead(d, m)
	if err != nil {
		return nil, err
	}

	if err := d.Set("name", id); err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func buildFolderSyncAllID(folderName string) string {
	return fmt.Sprintf("%s", folderName)
}
