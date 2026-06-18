package akeyless

import (
	"context"
	"fmt"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceFolderSync() *schema.Resource {
	return &schema.Resource{
		Description: "Folder sync resource",
		Create:      resourceFolderSyncCreate,
		Read:        resourceFolderSyncRead,
		Update:      resourceFolderSyncUpdate,
		Delete:      resourceFolderSyncDelete,
		Importer: &schema.ResourceImporter{
			State: resourceFolderSyncImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Folder name",
				ForceNew:    true,
			},
			"usc_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Universal Secret Connector name, If not provided all attached USC's will be synced",
				ForceNew:    true,
			},
			"namespace": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Vault namespace, relevant only for Hashicorp Vault Target",
			},
			"engine_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Hashi Vault engine name prefix, must end with '/'",
			},
			"delete_remote": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Delete the secret from the remote target as well",
			},
			"delete_from_usc": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Delete the secrets from the remote target usc as well",
			},
		},
	}
}

func resourceFolderSyncCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	folderName := d.Get("name").(string)
	uscName := d.Get("usc_name").(string)
	namespace := d.Get("namespace").(string)
	engineName := d.Get("engine_name").(string)
	deleteRemote := d.Get("delete_remote").(bool)

	body := akeyless_api.FolderSync{
		Name:          folderName,
		Token:         &token,
		Accessibility: akeyless_api.PtrString("regular"),
		Json:          akeyless_api.PtrBool(false),
	}
	common.GetAkeylessPtr(&body.UscName, uscName)
	common.GetAkeylessPtr(&body.Namespace, namespace)
	common.GetAkeylessPtr(&body.EngineName, engineName)
	common.GetAkeylessPtr(&body.DeleteRemote, deleteRemote)

	_, resp, err := client.FolderSync(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't sync folder", resp, err)
	}

	d.SetId(buildFolderSyncID(folderName, uscName))

	return nil
}

func resourceFolderSyncRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	folderName, uscName, err := extractFolderSyncID(d.Id())
	if err != nil {
		return err
	}

	body := akeyless_api.FolderGet{
		Name:  folderName,
		Token: &token,
	}

	rOut, res, err := client.FolderGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get folder", res, err)
	}
	if rOut.Folder == nil {
		return fmt.Errorf("folder sync not found for folder name: %s, usc name: %s", folderName, uscName)
	}

	normalizedUscName := strings.TrimPrefix(uscName, "/")
	for _, syncConfig := range rOut.Folder.UscSyncConfigs {
		if syncConfig.UscItemName == nil {
			continue
		}
		if strings.TrimPrefix(*syncConfig.UscItemName, "/") != normalizedUscName {
			continue
		}

		if syncConfig.Namespace != nil {
			if err = d.Set("namespace", *syncConfig.Namespace); err != nil {
				return err
			}
		}
		if syncConfig.EngineName != nil {
			if err = d.Set("engine_name", *syncConfig.EngineName); err != nil {
				return err
			}
		}
		if syncConfig.DeleteRemote != nil {
			if err = d.Set("delete_remote", *syncConfig.DeleteRemote); err != nil {
				return err
			}
		}

		d.SetId(buildFolderSyncID(folderName, uscName))
		return nil
	}

	d.SetId("")
	return nil
}

func resourceFolderSyncUpdate(d *schema.ResourceData, m interface{}) error {
	return nil
}

func resourceFolderSyncDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	folderName, uscName, err := extractFolderSyncID(d.Id())
	if err != nil {
		return err
	}

	deleteFromUsc := d.Get("delete_from_usc").(bool)
	body := akeyless_api.FolderDeleteSync{
		Name:          folderName,
		UscName:       uscName,
		Token:         &token,
		Accessibility: akeyless_api.PtrString("regular"),
		Json:          akeyless_api.PtrBool(false),
	}
	common.GetAkeylessPtr(&body.DeleteFromUsc, deleteFromUsc)

	_, _, err = client.FolderDeleteSync(ctx).Body(body).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceFolderSyncImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()

	err := resourceFolderSyncRead(d, m)
	if err != nil {
		return nil, err
	}

	folderName, uscName, err := extractFolderSyncID(id)
	if err != nil {
		return nil, err
	}

	if err = d.Set("name", folderName); err != nil {
		return nil, err
	}
	if err = d.Set("usc_name", uscName); err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

const folderSyncDelimiter string = "__"

func buildFolderSyncID(folderName, uscName string) string {
	return strings.Join([]string{folderName, uscName}, folderSyncDelimiter)
}

func extractFolderSyncID(id string) (string, string, error) {
	fields := strings.Split(id, folderSyncDelimiter)
	if len(fields) != 2 {
		return "", "", fmt.Errorf("invalid id format: %s. expected format 'folderName__uscName'", id)
	}
	return fields[0], fields[1], nil
}
