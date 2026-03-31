package gateway

import (
	"context"
	"fmt"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/tests/testutils"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestEventForwarderEmail(t *testing.T) {
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	eventForwarderName := "test-event-forwarder-email"

	config := fmt.Sprintf(`
		resource "akeyless_event_forwarder_email" "%v" {
			name = "%v"
			items_event_source_locations = ["/items/*"]
			targets_event_source_locations = ["/targets/*"]
			auth_methods_event_source_locations = ["/auth-methods/*"]
			event_types = ["request-access", "certificate-pending-expiration", "email-auth-method-approved", "usage", "rotation-usage", "gateway-inactive", "static-secret-updated", "rate-limiting", "usage-report"]
			email_to = "sendmemail@akeyless.io,sendmemail2@akeyless.io"
			override_url = "https://example.com"
			include_error = "true"
			runner_type = "periodic"
			every = "1"
			enable = "true"
			description = "test email event forwarder"
		}
	`, eventForwarderName, eventForwarderName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_event_forwarder_email" "%v" {
			name = "%v"
			items_event_source_locations = ["items/*", "items2"]
			targets_event_source_locations = ["targets/*", "targets2/*"]
			event_types = ["secret-sync", "request-access", "gateway-inactive", "static-secret-updated", "rate-limiting", "usage-report"]
			email_to = "sendmemail123@akeyless.io"
			override_url = "https://example2.com"
			include_error = "false"
			runner_type = "periodic"
			every = "1"
			enable = "true"
			keep_prev_version = "true"
			description = "test email event forwarder update"
        }
	`, eventForwarderName, eventForwarderName)

	testEventForwarderResource(t, eventForwarderName, config, configUpdate)
}

func TestEventForwarderWebhook(t *testing.T) {
	t.Skip("skipping: gateway rejects unregistered cluster URLs in gateways_event_source_locations")
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	eventForwarderName := "test-event-forwarder-webhook"

	config := fmt.Sprintf(`
		resource "akeyless_event_forwarder_webhook" "%v" {
			name = "%v"
			items_event_source_locations = ["/items/*"]
			targets_event_source_locations = ["/targets/*"]
			auth_methods_event_source_locations = ["/auth-methods/*"]
			gateways_event_source_locations = ["http://localhost:8000"]
			event_types = ["secret-sync", "request-access", "gateway-inactive", "static-secret-updated", "rate-limiting", "usage-report"]
			url = "https://example.com"
			auth_type = "user-pass"
			username = "myusername"
			password = "mypassword"
			runner_type = "immediate"
			enable = "true"
			description = "test webhook event forwarder"
		}
	`, eventForwarderName, eventForwarderName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_event_forwarder_webhook" "%v" {
			name = "%v"
			items_event_source_locations = ["items/*", "items2"]
			targets_event_source_locations = ["targets/*", "targets2/*"]
			auth_methods_event_source_locations = ["/auth/"]
			gateways_event_source_locations = ["http://localhost:8000"]
			event_types = ["secret-sync", "request-access", "gateway-inactive", "static-secret-updated", "usage-report"]
			url = "https://example2.com"
			auth_type = "user-pass"
			username = "myusername2"
			password = "mypassword2"
			runner_type = "periodic"
			every = "2"
			enable = "true"
			keep_prev_version = "true"
			description = "test webhook event forwarder update"
		}
	`, eventForwarderName, eventForwarderName)

	testEventForwarderResource(t, eventForwarderName, config, configUpdate)
}

func TestEventForwarderServicenow(t *testing.T) {
	t.Skip("skipping: gateway rejects unregistered cluster URLs in gateways_event_source_locations")
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	eventForwarderName := "test-event-forwarder-servicenow"

	config := fmt.Sprintf(`
		resource "akeyless_event_forwarder_service_now" "%v" {
			name = "%v"
			items_event_source_locations = ["/items/*"]
			targets_event_source_locations = ["/targets/*"]
			auth_methods_event_source_locations = ["/auth-methods/*"]
			gateways_event_source_locations = ["http://localhost:8000"]
			event_types = ["secret-sync", "request-access", "gateway-inactive", "static-secret-updated", "rate-limiting", "usage-report"]
			host = "https://example.com"
			admin_name = "myusername"
			admin_pwd = "mypassword"
			runner_type = "immediate"
			description = "test servicenow event forwarder"
		}
	`, eventForwarderName, eventForwarderName)

	base64Key := "XXXXXX"
	configUpdate := fmt.Sprintf(`
		resource "akeyless_event_forwarder_service_now" "%v" {
			name = "%v"
			items_event_source_locations = ["items/*", "items2"]
			targets_event_source_locations = ["targets/*", "targets2/*"]
			auth_methods_event_source_locations = ["/auth/"]
			gateways_event_source_locations = ["http://localhost:8000"]
			event_types = ["secret-sync", "request-access", "gateway-inactive", "static-secret-updated", "usage-report"]
			host = "https://example2.com"
			auth_type = "jwt"
			user_email = "myusername2@asa.com"
			client_id = "myclientid"
			client_secret = "myclientsecret"
			app_private_key_base64 = "%v"
			runner_type = "immediate"
			description = "test servicenow event forwarder update"
		}
	`, eventForwarderName, eventForwarderName, base64Key)

	testEventForwarderResource(t, eventForwarderName, config, configUpdate)
}

func TestEventForwarderSlack(t *testing.T) {
	t.Skip("skipping: gateway rejects unregistered cluster URLs in gateways_event_source_locations")
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	eventForwarderName := "test-event-forwarder-slack"

	config := fmt.Sprintf(`
		resource "akeyless_event_forwarder_slack" "%v" {
			name = "%v"
			items_event_source_locations = ["/items/*"]
			targets_event_source_locations = ["/targets/*"]
			auth_methods_event_source_locations = ["/auth-methods/*"]
			gateways_event_source_locations = ["http://localhost:8000"]
			event_types = ["secret-sync", "request-access", "gateway-inactive", "static-secret-updated", "rate-limiting", "usage-report"]
			url = "https://example.com"
			runner_type = "immediate"
			description = "test slack event forwarder"
		}
	`, eventForwarderName, eventForwarderName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_event_forwarder_slack" "%v" {
			name = "%v"
			items_event_source_locations = ["items/*", "items2"]
			targets_event_source_locations = ["targets/*", "targets2/*"]
			auth_methods_event_source_locations = ["/auth/"]
			gateways_event_source_locations = ["http://localhost:8000"]
			event_types = ["secret-sync", "request-access", "gateway-inactive", "static-secret-updated", "usage-report"]
			url = "https://example2.com"
			runner_type = "immediate"
			description = "test slack event forwarder update"
		}
	`, eventForwarderName, eventForwarderName)

	testEventForwarderResource(t, eventForwarderName, config, configUpdate)
}

func TestEventForwarderTeams(t *testing.T) {
	t.Skip("skipping: gateway rejects unregistered cluster URLs in gateways_event_source_locations")
	testutils.SkipIfNoGateway(t)
	t.Parallel()

	eventForwarderName := "test-event-forwarder-teams"

	config := fmt.Sprintf(`
		resource "akeyless_event_forwarder_teams" "%v" {
			name = "%v"
			items_event_source_locations = ["/items/*"]
			targets_event_source_locations = ["/targets/*"]
			auth_methods_event_source_locations = ["/auth-methods/*"]
			gateway_event_source_locations = ["http://localhost:8000"]
			event_types = ["secret-sync", "request-access", "gateway-inactive", "static-secret-updated", "rate-limiting", "usage-report"]
			url = "https://example.webhook.office.com"
			runner_type = "immediate"
			description = "test teams event forwarder"
		}
	`, eventForwarderName, eventForwarderName)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_event_forwarder_teams" "%v" {
			name = "%v"
			items_event_source_locations = ["items/*", "items2"]
			targets_event_source_locations = ["targets/*", "targets2/*"]
			auth_methods_event_source_locations = ["/auth/"]
			gateway_event_source_locations = ["http://localhost:8000"]
			event_types = ["secret-sync", "request-access", "gateway-inactive", "static-secret-updated", "usage-report"]
			url = "https://example2.webhook.office.com"
			runner_type = "immediate"
			description = "test teams event forwarder update"
		}
	`, eventForwarderName, eventForwarderName)

	testEventForwarderResource(t, eventForwarderName, config, configUpdate)
}

func testEventForwarderResource(t *testing.T, eventForwarderName string, configs ...string) {
	steps := make([]resource.TestStep, len(configs))
	for i, config := range configs {
		steps[i] = resource.TestStep{
			Config: config,
			Check: resource.ComposeTestCheckFunc(
				checkEventForwarderExistsRemotely(eventForwarderName),
			),
		}
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps:             steps,
	})
}

func checkEventForwarderExistsRemotely(eventForwarderName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := testutils.GetClient()
		if err != nil {
			return err
		}

		body := akeyless_api.EventForwarderGet{
			Name:  eventForwarderName,
			Token: &token,
		}

		_, _, err = client.EventForwarderGet(context.Background()).Body(body).Execute()
		if err != nil {
			return err
		}
		return nil
	}
}
