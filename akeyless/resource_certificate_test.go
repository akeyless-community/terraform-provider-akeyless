package akeyless

import (
	"context"
	"fmt"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestCertificateResource(t *testing.T) {

	t.Parallel()

	certificateName := "test_certificate6"
	certificatePath := testPath(certificateName)
	keyData, cert := generateCertForTest(t, 1024)
	keyData2, cert2 := generateCertForTest(t, 1024)

	config := fmt.Sprintf(`
		resource "akeyless_certificate" "%v" {
			name 				= "%v"
			certificate_data 	= "%v"
			format 				= "pem"
			key_data 			= "%v"
			expiration_event_in = ["30"]
			tags 				= ["t1", "t2"]
			description 		= "certificate description"
			delete_protection  	= "true"
		}
	`, certificateName, certificatePath, cert, keyData)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_certificate" "%v" {
			name 				= "%v"
			certificate_data	= "%v"
			tags 				= ["t1", "t3"]
			description 		= "updated certificate description"
		}
	`, certificateName, certificatePath, cert2)

	configUpdate2 := fmt.Sprintf(`
		resource "akeyless_certificate" "%v" {
			name 				= "%v"
			certificate_data 	= "%v"
			format 				= "pem"
			key_data 			= "%v"
			expiration_event_in = ["20"]
			description 		= "updated certificate description again"
			delete_protection  	= "false"
		}
	`, certificateName, certificatePath, cert2, keyData2)

	testCertificateResource(t, certificatePath, config, configUpdate, configUpdate2)
}

func testCertificateResource(t *testing.T, certificatePath string, configs ...string) {
	steps := make([]resource.TestStep, len(configs))
	for i, config := range configs {
		steps[i] = resource.TestStep{
			Config: config,
			Check: resource.ComposeTestCheckFunc(
				checkCertificateExistsRemotely(certificatePath),
			),
		}
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps:             steps,
	})
}

func checkCertificateExistsRemotely(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := *testAccProvider.Meta().(*providerMeta).client
		token := *testAccProvider.Meta().(*providerMeta).token

		gsvBody := akeyless_api.GetCertificateValue{
			Name:  &path,
			Token: &token,
		}

		_, _, err := client.GetCertificateValue(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}

		return nil
	}
}
