package gateway

import (
	"fmt"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestStaticSecretSyncResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	secretName := "test_static_secret_for_sync"
	secretPath := testPath(secretName)
	targetName := "target_hashi_for_sync"
	targetPath := testPath(targetName)
	uscName := "usc_for_sync"
	uscPath := testPath(uscName)
	remoteSecretName := "secret/data/example"

	config := fmt.Sprintf(`
        resource "akeyless_target_hashivault" "%v" {
            name        = "%v"
            hashi_url   = "http://127.0.0.1:8200"
            vault_token = "test"
        }

        resource "akeyless_usc" "%v" {
            name                = "%v"
            target_to_associate = akeyless_target_hashivault.%v.name
            depends_on          = [akeyless_target_hashivault.%v]
        }

        resource "akeyless_static_secret" "%v" {
            path   = "%v"
            value  = "{\"k\":\"v\"}"
            format = "json"
        }

        resource "akeyless_static_secret_sync" "sync" {
            name               = akeyless_static_secret.%v.path
            usc_name           = akeyless_usc.%v.name
            remote_secret_name = "%v"
            depends_on         = [akeyless_static_secret.%v, akeyless_usc.%v]
        }
    `, targetName, targetPath,
		uscName, uscPath, targetName, targetName,
		secretName, secretPath,
		secretName, uscName, remoteSecretName, secretName, uscName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
			},
		},
	})
}

func TestRotatedSecretSyncResource(t *testing.T) {

	t.Skip("Skip until fixing bug in GW: UseCapitalLetters and UseCapitalLettersV2 should allow empty strings")

	testutils.SkipIfNoGateway(t)

	hashiTargetName := "target_hashi_for_rs_sync"
	hashiTargetPath := testPath(hashiTargetName)
	uscName := "usc_for_rs_sync"
	uscPath := testPath(uscName)
	rsName := "test_rotated_secret_for_sync"
	rsPath := testPath(rsName)
	targetName := "target_web_for_rs_sync"
	targetPath := testPath(targetName)
	targetDetailsType := "web_target_details"

	expect := map[string]any{
		"url": "http://127.0.0.1:51790/sync/rotate",
	}
	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	t.Cleanup(func() {
		testutils.DeleteTarget(t, targetPath)
	})

	remoteSecretName := "secret/data/rs-example"

	config := fmt.Sprintf(`
        resource "akeyless_target_hashivault" "%v" {
            name        = "%v"
            hashi_url   = "http://127.0.0.1:8200"
            vault_token = "test"
        }

        resource "akeyless_usc" "%v" {
            name                = "%v"
            target_to_associate = akeyless_target_hashivault.%v.name
            depends_on          = [akeyless_target_hashivault.%v]
        }

        resource "akeyless_rotated_secret_custom" "%v" {
            name           = "%v"
            target_name    = "%v"
            custom_payload = "p1"
        }

        resource "akeyless_rotated_secret_sync" "sync" {
            name               = akeyless_rotated_secret_custom.%v.name
            usc_name           = akeyless_usc.%v.name
            remote_secret_name = "%v"
            depends_on         = [akeyless_rotated_secret_custom.%v, akeyless_usc.%v]
        }
    `, hashiTargetName, hashiTargetPath,
		uscName, uscPath, hashiTargetName, hashiTargetName,
		rsName, rsPath, targetPath,
		rsName, uscName, remoteSecretName, rsName, uscName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
			},
		},
	})
}

func TestFolderSyncResource(t *testing.T) {
	testutils.SkipIfNoGateway(t)

	hashiTargetName := "target_hashi_for_folder_sync"
	hashiTargetPath := testPath(hashiTargetName)
	uscName := "usc_for_folder_sync"
	uscPath := testPath(uscName)
	folderName := "folder_for_sync"
	folderPath := testPath(folderName)
	secretName := "sync_secret"
	secretPath := folderPath + "/" + secretName

	config := fmt.Sprintf(`
		resource "akeyless_target_hashivault" "%v" {
			name        = "%v"
			hashi_url   = "http://127.0.0.1:8200"
			vault_token = "test"
		}

		resource "akeyless_usc" "%v" {
			name                = "%v"
			target_to_associate = akeyless_target_hashivault.%v.name
			depends_on          = [akeyless_target_hashivault.%v]
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

		resource "akeyless_folder_sync" "sync" {
			name               = akeyless_folder.%v.name
			usc_name           = akeyless_usc.%v.name
			engine_name        = "secret/data/"
			delete_remote      = true
			depends_on         = [akeyless_static_secret.%v, akeyless_usc.%v]
		}
	`, hashiTargetName, hashiTargetPath,
		uscName, uscPath, hashiTargetName, hashiTargetName,
		folderName, folderPath,
		secretName, secretPath, folderName,
		folderName, uscName, secretName, uscName)

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
