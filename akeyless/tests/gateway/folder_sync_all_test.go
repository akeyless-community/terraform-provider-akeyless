package gateway

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"
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

	t.Cleanup(func() {
		deleteFolderSyncConfig(t, folderPath, uscPath1)
		deleteFolderSyncConfig(t, folderPath, uscPath2)
	})

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
	`, folderName, folderPath,
		secretName, secretPath, folderName,
	)

	configUpdate := fmt.Sprintf(`
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
			},
			{
				PreConfig: func() {
					createFolderSyncConfig(t, folderPath, uscPath1)
					createFolderSyncConfig(t, folderPath, uscPath2)
				},
				Config: configUpdate,
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

func createFolderSyncConfig(t *testing.T, folderName, uscName string) {
	t.Helper()

	client, token, err := testutils.GetClient()
	require.NoError(t, err)

	body := akeyless_api.FolderSync{
		Name:          folderName,
		Token:         &token,
		Accessibility: akeyless_api.PtrString("regular"),
		Json:          akeyless_api.PtrBool(false),
		DeleteRemote:  akeyless_api.PtrBool(true),
		EngineName:    akeyless_api.PtrString("secret/data/"),
		UscName:       akeyless_api.PtrString(uscName),
	}

	_, resp, err := client.FolderSync(context.Background()).Body(body).Execute()
	if err != nil {
		t.Fatalf("can't create folder sync for test: %v", common.HandleError("can't create folder sync for test", resp, err))
	}

	t.Logf("created folder sync for folder %s and usc %s", folderName, uscName)
}

func deleteFolderSyncConfig(t *testing.T, folderName, uscName string) {
	t.Helper()

	client, token, err := testutils.GetClient()
	if err != nil {
		t.Logf("skip folder sync cleanup for folder %s and usc %s: %v", folderName, uscName, err)
		return
	}

	body := akeyless_api.FolderDeleteSync{
		Name:          folderName,
		UscName:       uscName,
		Token:         &token,
		Accessibility: akeyless_api.PtrString("regular"),
		Json:          akeyless_api.PtrBool(false),
	}

	_, resp, err := client.FolderDeleteSync(context.Background()).Body(body).Execute()
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "404 Not Found") ||
			strings.Contains(errStr, "NotFound") ||
			strings.Contains(errStr, "400 Bad Request") {
			t.Logf("folder sync cleanup skipped for folder %s and usc %s: %v", folderName, uscName, err)
			return
		}
		require.Fail(t, common.HandleError("can't delete folder sync for test", resp, err).Error())
	}

	t.Logf("deleted folder sync for folder %s and usc %s", folderName, uscName)
}
