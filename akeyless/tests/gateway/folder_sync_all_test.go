package gateway

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
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

	uscName2 := "usc_for_folder_sync_all_2"
	uscPath2 := testPath(uscName2)

	folderName := "folder_for_sync_all"
	folderPath := testPath(folderName)
	secretName := "sync_all_secret"
	secretPath := folderPath + "/" + secretName

	config := fmt.Sprintf(`
		resource "akeyless_usc" "%v" {
			name                = "%v"
			target_to_associate = "%v"
		}

		resource "akeyless_usc" "%v" {
			name                = "%v"
			target_to_associate = "%v"
		}

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
			name          = akeyless_folder.%v.name
			accessibility = "regular"
			depends_on = [akeyless_static_secret.%v, akeyless_usc.%v, akeyless_usc.%v]
		}
	`, uscName1, uscPath1, targetPath,
		uscName2, uscPath2, targetPath,
		folderName, folderPath,
		secretName, secretPath, folderName,
		folderName, secretName, uscName1, uscName2)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_folder_sync_all.sync_all", "accessibility", "regular"),
					checkFolderSyncExistsRemotelyEventually(folderPath, uscPath1, 15, 2*time.Second),
					checkFolderSyncExistsRemotelyEventually(folderPath, uscPath2, 15, 2*time.Second),
				),
			},
		},
	})
}

func checkFolderSyncExistsRemotelyEventually(folder, uscName string, attempts int, delay time.Duration) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		var lastErr error
		for attempt := 0; attempt < attempts; attempt++ {
			err := testutils.CheckFolderSyncExistsRemotely(folder, uscName)(s)
			if err == nil {
				return nil
			}

			errStr := err.Error()
			if !strings.Contains(errStr, "folder sync not found") &&
				!strings.Contains(errStr, "404 Not Found") &&
				!strings.Contains(errStr, "NotFound") {
				return err
			}

			lastErr = err
			time.Sleep(delay)
		}

		return lastErr
	}
}
