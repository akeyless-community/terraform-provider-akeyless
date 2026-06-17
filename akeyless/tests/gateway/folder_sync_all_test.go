package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestFolderSyncAllResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	testutils.SkipIfNoVault(t)

	targetName := "target_hashi_for_folder_sync_all"
	targetPath := testPath(targetName)
	targetDetailsType := "hashi_target_details"

	expect := map[string]any{
		"vault_url":        HashiVaultUrl,
		"vault_token":      HashiVaultToken,
		"vault_namespaces": "",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	uscName1 := "usc_for_folder_sync_all_1"
	uscPath1 := testPath(uscName1)
	createUsc(t, uscPath1, targetPath, uscOptions{})
	defer testutils.DeleteItem(t, uscPath1)

	uscName2 := "usc_for_folder_sync_all_2"
	uscPath2 := testPath(uscName2)
	createUsc(t, uscPath2, targetPath, uscOptions{})
	defer testutils.DeleteItem(t, uscPath2)

	folderName := "folder_for_sync_all"
	folderPath := testPath(folderName)
	secretName := "sync_all_secret"
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

		resource "akeyless_folder_sync_all" "sync_all" {
			name       = akeyless_folder.%v.name
			depends_on = [akeyless_static_secret.%v]
		}
	`, folderName, folderPath,
		secretName, secretPath, folderName,
		folderName, secretName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testutils.CheckFolderSyncExistsRemotely(folderPath, uscPath1),
					testutils.CheckFolderSyncExistsRemotely(folderPath, uscPath2),
				),
			},
		},
	})
}
