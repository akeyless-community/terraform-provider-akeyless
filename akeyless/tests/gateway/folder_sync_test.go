package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestFolderSyncWithUscResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	testutils.SkipIfNoVault(t)

	targetName := "target_hashi_for_folder_sync_one"
	targetPath := testPath(targetName)
	targetDetailsType := "hashi_target_details"

	expect := map[string]any{
		"vault_url":        HashiVaultUrl,
		"vault_token":      HashiVaultToken,
		"vault_namespaces": "",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	uscName := "usc_for_folder_sync_one"
	uscPath := testPath(uscName)
	createUsc(t, uscPath, targetPath, uscOptions{})
	defer testutils.DeleteItem(t, uscPath)

	folderName := "folder_for_sync_one"
	folderPath := testPath(folderName)
	secretName := "sync_one_secret"
	secretPath := folderPath + "/" + secretName

	config := fmt.Sprintf(`
		resource "akeyless_folder" "%v" {
			name = "%v"
		}

		resource "akeyless_static_secret" "%v" {
			path   = "%v"
			value  = "{\"k\":\"v\"}"
			format = "json"
			depends_on = [akeyless_folder.%v]
		}

		resource "akeyless_folder_sync" "sync" {
			name          = akeyless_folder.%v.name
			usc_name      = "%v"
			engine_name   = "secret/data/"
			delete_remote = true
			depends_on    = [akeyless_static_secret.%v]
		}
	`, folderName, folderPath,
		secretName, secretPath, folderName,
		folderName, uscName, secretName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckFolderSyncExistsRemotely(folderPath, uscPath),
					resource.TestCheckResourceAttr("akeyless_folder_sync.sync", "engine_name", "secret/data/"),
					resource.TestCheckResourceAttr("akeyless_folder_sync.sync", "delete_remote", "true"),
				),
			},
		},
	})
}
