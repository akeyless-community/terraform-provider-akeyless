package no_gateway

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccountCustomFieldResource(t *testing.T) {

	fieldName := fmt.Sprintf("test_custom_field_%s", testRunID)

	config := fmt.Sprintf(`
		resource "akeyless_account_custom_field" "test" {
			name        = "%s"
			object      = "ITEM"
			object_type = "STATIC_SECRET"
			required    = true
		}
	`, fieldName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_account_custom_field" "test" {
			name        = "%s_updated"
			object_type = "STATIC_SECRET"
			required    = false
		}
	`, fieldName)

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy: func(s *terraform.State) error {
			client, token, err := testutils.GetClient()
			if err != nil {
				return err
			}
			for _, rs := range s.RootModule().Resources {
				if rs.Type != "akeyless_account_custom_field" {
					continue
				}
				parsedId, err := strconv.ParseInt(rs.Primary.ID, 10, 64)
				if err != nil {
					return fmt.Errorf("invalid id %q: %w", rs.Primary.ID, err)
				}
				body := akeyless_api.AccountCustomFieldGet{
					Id:    parsedId,
					Token: &token,
				}
				_, res, err := client.AccountCustomFieldGet(context.Background()).Body(body).Execute()
				if err == nil {
					return fmt.Errorf("account custom field %s still exists", rs.Primary.ID)
				}
				if res != nil && res.StatusCode != 404 {
					return fmt.Errorf("account custom field %s still exists with status %d", rs.Primary.ID, res.StatusCode)
				}
			}
			return nil
		},
		Steps: []resource.TestStep{
			{Config: config},
			{Config: configUpdate},
		},
	})
}

func TestAccountSettingsResource(t *testing.T) {

	config := `
		resource "akeyless_account_settings" "test" {
			jwt_ttl_default                        = 120
			jwt_ttl_min                            = 10
			jwt_ttl_max                            = 360
			password_length                        = 12
			use_capital_letters                    = "true"
			use_lower_letters                      = "true"
			use_numbers                            = "true"
			use_special_characters                 = "true"
			dynamic_secret_max_ttl                 = 1440
			dynamic_secret_max_ttl_enable          = "true"
			items_deletion_protection              = "true"
			hide_static_password                   = "true"
			invalid_characters                     = "<>"
			item_locking_enabled                   = "true"
			enable_password_expiration             = "true"
			password_expiration_days               = "90"
			password_expiration_notification_days  = "14"
			default_share_link_ttl_minutes         = "60"
			enable_item_sharing                    = "true"
			company_name                           = "TestCompanyAcc"
		}
	`

	configUpdate := `
		resource "akeyless_account_settings" "test" {
			jwt_ttl_default                        = 60
			jwt_ttl_min                            = 5
			jwt_ttl_max                            = 720
			password_length                        = 8
			use_capital_letters                    = "false"
			use_lower_letters                      = "false"
			use_numbers                            = "false"
			use_special_characters                 = "false"
			dynamic_secret_max_ttl                 = 720
			dynamic_secret_max_ttl_enable          = "true"
			items_deletion_protection              = "false"
			hide_static_password                   = "false"
			invalid_characters                     = ""
			item_locking_enabled                   = "false"
			enable_password_expiration             = "false"
			password_expiration_days               = ""
			password_expiration_notification_days  = ""
			default_share_link_ttl_minutes         = ""
			enable_item_sharing                    = "false"
			company_name                           = "TestCompanyAccUpd"
		}
	`

	configUpdate2 := `
		resource "akeyless_account_settings" "test" {
			jwt_ttl_default                        = 60
			jwt_ttl_min                            = 5
			jwt_ttl_max                            = 720
			dynamic_secret_max_ttl_enable          = "false"
			password_length                        = 12
		}
	`

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "jwt_ttl_default", "120"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "jwt_ttl_min", "10"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "jwt_ttl_max", "360"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "password_length", "12"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "use_capital_letters", "true"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "use_lower_letters", "true"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "use_numbers", "true"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "use_special_characters", "true"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "dynamic_secret_max_ttl", "1440"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "dynamic_secret_max_ttl_enable", "true"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "items_deletion_protection", "true"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "hide_static_password", "true"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "invalid_characters", "<>"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "item_locking_enabled", "true"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "enable_password_expiration", "true"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "password_expiration_days", "90"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "password_expiration_notification_days", "14"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "default_share_link_ttl_minutes", "60"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "enable_item_sharing", "true"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "company_name", "TestCompanyAcc"),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "jwt_ttl_default", "60"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "jwt_ttl_min", "5"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "jwt_ttl_max", "720"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "password_length", "8"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "use_capital_letters", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "use_lower_letters", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "use_numbers", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "use_special_characters", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "dynamic_secret_max_ttl", "720"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "dynamic_secret_max_ttl_enable", "true"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "items_deletion_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "hide_static_password", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "invalid_characters", ""),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "item_locking_enabled", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "enable_password_expiration", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "password_expiration_days", ""),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "password_expiration_notification_days", ""),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "default_share_link_ttl_minutes", ""),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "enable_item_sharing", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "company_name", "TestCompanyAccUpd"),
				),
			},
			{
				Config: configUpdate2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "jwt_ttl_default", "60"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "jwt_ttl_min", "5"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "jwt_ttl_max", "720"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "password_length", "12"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "use_capital_letters", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "use_lower_letters", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "use_numbers", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "use_special_characters", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "dynamic_secret_max_ttl", "720"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "dynamic_secret_max_ttl_enable", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "items_deletion_protection", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "hide_static_password", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "invalid_characters", ""),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "item_locking_enabled", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "enable_password_expiration", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "password_expiration_days", ""),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "password_expiration_notification_days", ""),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "default_share_link_ttl_minutes", ""),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "enable_item_sharing", "false"),
					resource.TestCheckResourceAttr("akeyless_account_settings.test", "company_name", "TestCompanyAccUpd"),
				),
			},
		},
	})
}
