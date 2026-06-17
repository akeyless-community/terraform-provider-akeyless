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

		resource "akeyless_folder_sync" "sync_1" {
			name          = akeyless_folder.%v.name
			usc_name      = akeyless_usc.%v.name
			engine_name   = "secret/data/"
			delete_remote = true
			depends_on    = [akeyless_folder.%v, akeyless_usc.%v]
		}

		resource "akeyless_folder_sync" "sync_2" {
			name          = akeyless_folder.%v.name
			usc_name      = akeyless_usc.%v.name
			engine_name   = "secret/data/"
			delete_remote = true
			depends_on    = [akeyless_folder.%v, akeyless_usc.%v]
		}

		resource "akeyless_static_secret" "%v" {
			path   = "%v"
			value  = "{\"k\":\"v\"}"
			format = "json"
			depends_on = [akeyless_folder.%v, akeyless_folder_sync.sync_1, akeyless_folder_sync.sync_2]
		}

		resource "akeyless_folder_sync_all" "sync_all" {
			name          = akeyless_folder.%v.name
			accessibility = "regular"
			depends_on = [akeyless_static_secret.%v, akeyless_folder_sync.sync_1, akeyless_folder_sync.sync_2]
		}
	`, uscName1, uscPath1, targetPath,
		uscName2, uscPath2, targetPath,
		folderName, folderPath,
		folderName, uscName1, folderName, uscName1,
		folderName, uscName2, folderName, uscName2,
		secretName, secretPath, folderName,
		folderName, secretName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_folder_sync_all.sync_all", "accessibility", "regular"),
					checkFolderSyncExistsRemotelyEventually(t, folderPath, uscPath1, 15, 2*time.Second),
					checkFolderSyncExistsRemotelyEventually(t, folderPath, uscPath2, 15, 2*time.Second),
				),
			},
		},
	})
}

func checkFolderSyncExistsRemotelyEventually(t *testing.T, folder, uscName string, attempts int, delay time.Duration) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		t.Helper()
		var lastErr error
		for attempt := 0; attempt < attempts; attempt++ {
			if attempt > 0 {
				t.Logf("retrying folder sync check for folder %s and usc %s (attempt %d/%d)", folder, uscName, attempt+1, attempts)
			}
			err := testutils.CheckFolderSyncExistsRemotely(folder, uscName)(s)
			if err == nil {
				t.Logf("folder sync found for folder %s and usc %s", folder, uscName)
				return nil
			}

			errStr := err.Error()
			if !strings.Contains(errStr, "folder sync not found") &&
				!strings.Contains(errStr, "404 Not Found") &&
				!strings.Contains(errStr, "NotFound") {
				t.Logf("folder sync check failed for folder %s and usc %s with non-retryable error: %v", folder, uscName, err)
				return err
			}

			t.Logf("folder sync not found yet for folder %s and usc %s: %v", folder, uscName, err)
			lastErr = err
			time.Sleep(delay)
		}

		t.Logf("folder sync check exhausted retries for folder %s and usc %s: %v", folder, uscName, lastErr)
		return lastErr
	}
}
