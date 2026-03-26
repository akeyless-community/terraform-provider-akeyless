package akeyless

import (
	"context"
	"fmt"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var checkCertificateDestroyed = func(s *terraform.State) error {
	client := *testAccProvider.Meta().(*providerMeta).client
	token := *testAccProvider.Meta().(*providerMeta).token

	for _, rs := range s.RootModule().Resources {
		if rs.Type == "akeyless_certificate" {
			body := akeyless_api.DescribeItem{
				Name:  rs.Primary.ID,
				Token: &token,
			}
			_, res, err := client.DescribeItem(context.Background()).Body(body).Execute()
			if err == nil {
				return fmt.Errorf("certificate %s still exists", rs.Primary.ID)
			}
			if res != nil && res.StatusCode != 404 {
				return fmt.Errorf("certificate %s: unexpected status %d", rs.Primary.ID, res.StatusCode)
			}
		}
	}
	return nil
}

func TestCertificateResource(t *testing.T) {

	t.Parallel()

	certificateName := "test_certificate"
	certificatePath := testPath(certificateName)
	keyData, cert := generateCertForTest(t, 1024)
	keyData2, cert2 := generateCertForTest(t, 1024)
	crt2 := convertPemCertToCrt(t, cert2)

	config := fmt.Sprintf(`
		resource "akeyless_certificate" "%v" {
			name 				= "%v"
			certificate_data 	= "%v"
			format 				= "pem"
			key_data 			= "%v"
			expiration_event_in = ["30"]
			tags 				= ["t1", "t2"]
			description 		= "certificate description"
			keep_prev_version	= "true"
			delete_protection  	= "true"
		}
	`, certificateName, certificatePath, cert, keyData)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_certificate" "%v" {
			name 				= "%v"
			certificate_data	= "%v"
			format 				= "crt"
			tags 				= ["t1", "t3"]
			description 		= "updated certificate description"
			keep_prev_version	= "false"
		}
	`, certificateName, certificatePath, crt2)

	configUpdate2 := fmt.Sprintf(`
		resource "akeyless_certificate" "%v" {
			name 				= "%v"
			certificate_data 	= "%v"
			format 				= "p12"
			key_data 			= "%v"
			expiration_event_in = ["20"]
			description 		= "updated certificate description again"
			delete_protection  	= "false"
		}
	`, certificateName, certificatePath, cert2, keyData2)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      checkCertificateDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					checkCertificateExistsRemotely(certificatePath),
					resource.TestCheckResourceAttr("akeyless_certificate."+certificateName, "keep_prev_version", "true"),
					resource.TestCheckResourceAttr("akeyless_certificate."+certificateName, "delete_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_certificate."+certificateName, "description", "certificate description"),
					resource.TestCheckResourceAttr("akeyless_certificate."+certificateName, "format", "pem"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					checkCertificateExistsRemotely(certificatePath),
					resource.TestCheckResourceAttr("akeyless_certificate."+certificateName, "description", "updated certificate description"),
					resource.TestCheckResourceAttr("akeyless_certificate."+certificateName, "format", "crt"),
				),
			},
			{
				Config: configUpdate2,
				Check: resource.ComposeTestCheckFunc(
					checkCertificateExistsRemotely(certificatePath),
					resource.TestCheckResourceAttr("akeyless_certificate."+certificateName, "delete_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_certificate."+certificateName, "description", "updated certificate description again"),
					resource.TestCheckResourceAttr("akeyless_certificate."+certificateName, "format", "p12"),
				),
			},
		},
	})
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
		CheckDestroy:      checkCertificateDestroyed,
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
