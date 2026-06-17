package gateway

import (
	"context"
	"encoding/json"
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

const GcpKey1 string = `{
  "type": "service_account",
  "project_id": "test",
  "private_key_id": "test",
  "private_key": "dGVzdA==",
  "client_email": "test@test.com",
  "client_id": "test",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test.com",
  "universe_domain": "googleapis.com"
}`

var (
	HashiVaultUrl   string = testutils.DockerVaultAddr
	HashiVaultToken string = testutils.VaultToken
)

func TestUscResourceHashi(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	testutils.SkipIfNoVault(t)

	targetName := "test-target-hashi"
	targetPath := testPath(targetName)
	targetDetailsType := "hashi_target_details"

	expect := map[string]any{
		"vault_url":        HashiVaultUrl,
		"vault_token":      HashiVaultToken,
		"vault_namespaces": "",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	uscName := "test-usc-hashi"
	uscPath := testPath(uscName)

	config := fmt.Sprintf(`
		resource "akeyless_usc" "%v" {
			name 				= "%v"
			target_to_associate = "%v"
			description 		= "aaaa"
		}
	`, uscName, uscPath, targetPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_usc" "%v" {
			name 				= "%v"
			target_to_associate = "%v"
			description 		= "bbbb"
		}
	`, uscName, uscPath, targetPath)

	testutils.TestItemResource(t, providerFactories, uscPath, config, configUpdate)
}

func TestUscSecretResourceHashi(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	testutils.SkipIfNoVault(t)

	targetName := "test-target-hashi"
	targetPath := testPath(targetName)
	targetDetailsType := "hashi_target_details"

	expect := map[string]any{
		"vault_url":        HashiVaultUrl,
		"vault_token":      HashiVaultToken,
		"vault_namespaces": "",
	}

	testutils.CreateTargetByType(t, targetPath, targetDetailsType, expect)
	defer testutils.DeleteTarget(t, targetPath)

	uscName := "test-usc-hashi"
	uscPath := testPath(uscName)

	createUsc(t, uscPath, targetPath, uscOptions{})
	defer testutils.DeleteItem(t, uscPath)

	secretName := "secret/test-"
	remoteSecretActivationDate := "2026-01-01T00:00:00Z"
	remoteSecretExpires := "2026-12-31T00:00:00Z"

	value1 := map[string]string{"key1": "value1"}
	marshalled1, err := json.Marshal(value1)
	require.NoError(t, err)
	val1 := common.Base64Encode(string(marshalled1))

	value2 := map[string]string{"key2": "value2"}
	marshalled2, err := json.Marshal(value2)
	require.NoError(t, err)
	val2 := common.Base64Encode(string(marshalled2))

	config := fmt.Sprintf(`
	resource "akeyless_usc_secret" "%v" {
		usc_name 		= "%v"
		secret_name 	= "%v"
		value 			= "%v"
		remote_secret_activation_date = "%v"
		remote_secret_expires         = "%v"
		description 	= "aaaa"
		tags			= ["tag1", "tag2"]
	}
`, uscName, uscPath, secretName, val1, remoteSecretActivationDate, remoteSecretExpires)

	configUpdate := fmt.Sprintf(`
	resource "akeyless_usc_secret" "%v" {
		usc_name 		= "%v"
		secret_name 	= "%v"
		value 			= "%v"
		remote_secret_activation_date = "%v"
		remote_secret_expires         = "%v"
		description 	= "bbbb"
		tags			= ["tag1", "tag3"]
	}
`, uscName, uscPath, secretName, val2, remoteSecretActivationDate, remoteSecretExpires)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkItemExistsRemotelyEventually(uscPath+"/"+secretName, 15, 2*time.Second),
					resource.TestCheckResourceAttr("akeyless_usc_secret."+uscName, "remote_secret_activation_date", remoteSecretActivationDate),
					resource.TestCheckResourceAttr("akeyless_usc_secret."+uscName, "remote_secret_expires", remoteSecretExpires),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkItemExistsRemotelyEventually(uscPath+"/"+secretName, 15, 2*time.Second),
					resource.TestCheckResourceAttr("akeyless_usc_secret."+uscName, "remote_secret_activation_date", remoteSecretActivationDate),
					resource.TestCheckResourceAttr("akeyless_usc_secret."+uscName, "remote_secret_expires", remoteSecretExpires),
				),
			},
		},
	})
}

func checkItemExistsRemotelyEventually(path string, attempts int, delay time.Duration) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		var lastErr error
		for attempt := 0; attempt < attempts; attempt++ {
			err := testutils.CheckItemExistsRemotely(path)(s)
			if err == nil {
				return nil
			}

			if !strings.Contains(err.Error(), "404 Not Found") && !strings.Contains(err.Error(), "NotFound") {
				return err
			}

			lastErr = err
			time.Sleep(delay)
		}

		return lastErr
	}
}

type uscOptions struct {
	azureKvName  string
	k8sNamespace string
}

func createUsc(t *testing.T, uscName, targetName string, opts uscOptions) {

	client, token, err := testutils.GetClient()
	require.NoError(t, err)

	body := akeyless_api.CreateUSC{
		Name:  uscName,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetToAssociate, targetName)
	common.GetAkeylessPtr(&body.AzureKvName, opts.azureKvName)
	common.GetAkeylessPtr(&body.K8sNamespace, opts.k8sNamespace)

	_, _, err = client.CreateUSC(context.Background()).Body(body).Execute()
	if err != nil {
		fmt.Println("failed to create usc for test:", err)
	} else {
		fmt.Println("created:", uscName)
	}
}
