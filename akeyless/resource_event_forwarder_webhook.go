// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"net/http"
)

func resourceEventForwarderWebhook() *schema.Resource {
	return &schema.Resource{
		Description: "Event Forwarder Webhook resource",
		Create:      resourceEventForwarderWebhookCreate,
		Read:        resourceEventForwarderWebhookRead,
		Update:      resourceEventForwarderWebhookUpdate,
		Delete:      resourceEventForwarderWebhookDelete,
		Importer: &schema.ResourceImporter{
			State: resourceEventForwarderWebhookImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Event Forwarder name",
				ForceNew:    true,
			},
			"items_event_source_locations": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Items event sources to forward events about, for example: /abc/*",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"targets_event_source_locations": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Targets event sources to forward events about, for example: /abc/*",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"auth_methods_event_source_locations": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Auth Methods event sources to forward events about, for example: /abc/*",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"gateways_event_source_locations": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Gateways event sources to forward events about,for example the relevant Gateways cluster urls,: http://localhost:8000.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"event_types": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A comma-separated list of types of events to notify about [request-access, certificate-pending-expiration, certificate-expired, certificate-provisioning-success, certificate-provisioning-failure, auth-method-pending-expiration, auth-method-expired, next-automatic-rotation, rotated-secret-success, rotated-secret-failure, dynamic-secret-failure, multi-auth-failure, uid-rotation-failure, apply-justification, email-auth-method-approved, usage, rotation-usage, gateway-inactive, static-secret-updated, rate-limiting, usage-report, secret-sync]",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Key name. The key will be used to encrypt the Event Forwarder secret value. If key name is not specified, the account default protection key is used",
			},
			"runner_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Event Forwarder runner type [immediate, periodic]",
				Default:     "immediate",
			},
			"every": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Rate of periodic runner repetition in hours",
			},
			"url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Webhook URL",
			},
			"server_certificates": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Base64 encoded PEM certificate of the Webhook",
			},
			"auth_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Webhook authentication type [user-pass, bearer-token, certificate]",
				Default:     "user-pass",
			},
			"username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Username for authentication relevant for user-pass auth-type",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Password for authentication relevant for user-pass auth-type",
			},
			"auth_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Base64 encoded Token string relevant for token auth-type",
			},
			"client_cert_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Base64 encoded PEM certificate, relevant for certificate auth-type",
			},
			"private_key_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Base64 encoded PEM RSA Private Key, relevant for certificate auth-type",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
		},
	}
}

func resourceEventForwarderWebhookCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	itemsEventSourceLocationsSet := d.Get("items_event_source_locations").(*schema.Set)
	itemsEventSourceLocations := common.ExpandStringList(itemsEventSourceLocationsSet.List())
	targetsEventSourceLocationsSet := d.Get("targets_event_source_locations").(*schema.Set)
	targetsEventSourceLocations := common.ExpandStringList(targetsEventSourceLocationsSet.List())
	authMethodsEventSourceLocationsSet := d.Get("auth_methods_event_source_locations").(*schema.Set)
	authMethodsEventSourceLocations := common.ExpandStringList(authMethodsEventSourceLocationsSet.List())
	gatewaysEventSourceLocationsSet := d.Get("gateways_event_source_locations").(*schema.Set)
	gatewaysEventSourceLocations := common.ExpandStringList(gatewaysEventSourceLocationsSet.List())
	eventTypesSet := d.Get("event_types").(*schema.Set)
	eventTypes := common.ExpandStringList(eventTypesSet.List())
	key := d.Get("key").(string)
	runnerType := d.Get("runner_type").(string)
	every := d.Get("every").(string)
	url := d.Get("url").(string)
	serverCertificates := d.Get("server_certificates").(string)
	authType := d.Get("auth_type").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	authToken := d.Get("auth_token").(string)
	clientCertData := d.Get("client_cert_data").(string)
	privateKeyData := d.Get("private_key_data").(string)
	description := d.Get("description").(string)

	body := akeyless_api.EventForwarderCreateWebhook{
		Name:       name,
		RunnerType: runnerType,
		Token:      &token,
	}
	common.GetAkeylessPtr(&body.ItemsEventSourceLocations, itemsEventSourceLocations)
	common.GetAkeylessPtr(&body.TargetsEventSourceLocations, targetsEventSourceLocations)
	common.GetAkeylessPtr(&body.AuthMethodsEventSourceLocations, authMethodsEventSourceLocations)
	common.GetAkeylessPtr(&body.GatewaysEventSourceLocations, gatewaysEventSourceLocations)
	common.GetAkeylessPtr(&body.EventTypes, eventTypes)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Every, every)
	common.GetAkeylessPtr(&body.Url, url)
	common.GetAkeylessPtr(&body.ServerCertificates, serverCertificates)
	common.GetAkeylessPtr(&body.AuthType, authType)
	common.GetAkeylessPtr(&body.Username, username)
	common.GetAkeylessPtr(&body.Password, password)
	common.GetAkeylessPtr(&body.AuthToken, authToken)
	common.GetAkeylessPtr(&body.ClientCertData, clientCertData)
	common.GetAkeylessPtr(&body.PrivateKeyData, privateKeyData)
	common.GetAkeylessPtr(&body.Description, description)

	_, resp, err := client.EventForwarderCreateWebhook(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Event Forwarder Webhook", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceEventForwarderWebhookRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	name := d.Id()

	body := akeyless_api.EventForwarderGet{
		Name:  name,
		Token: &token,
	}

	readOut, res, err := client.EventForwarderGet(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}

	rOut := readOut.EventForwarder

	if rOut.NotiForwarderType != nil {
		if *rOut.NotiForwarderType != "webhook" {
			return fmt.Errorf("resource type is not webhook")
		}
	}

	err = common.SetCommonEventForwarderVars(d, rOut)
	if err != nil {
		return err
	}

	if rOut.WebhookNotiForwarderPublicDetails != nil {
		if rOut.WebhookNotiForwarderPublicDetails.EndpointUrl != nil {
			err = d.Set("url", *rOut.WebhookNotiForwarderPublicDetails.EndpointUrl)
			if err != nil {
				return err
			}
		}
		if rOut.WebhookNotiForwarderPublicDetails.AuthType != nil {
			err = d.Set("auth_type", *rOut.WebhookNotiForwarderPublicDetails.AuthType)
			if err != nil {
				return err
			}
		}
		if rOut.WebhookNotiForwarderPublicDetails.Username != nil {
			err = d.Set("username", *rOut.WebhookNotiForwarderPublicDetails.Username)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(name)

	return nil
}

func resourceEventForwarderWebhookUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	itemsEventSourceLocationsSet := d.Get("items_event_source_locations").(*schema.Set)
	itemsEventSourceLocations := common.ExpandStringList(itemsEventSourceLocationsSet.List())
	targetsEventSourceLocationsSet := d.Get("targets_event_source_locations").(*schema.Set)
	targetsEventSourceLocations := common.ExpandStringList(targetsEventSourceLocationsSet.List())
	authMethodsEventSourceLocationsSet := d.Get("auth_methods_event_source_locations").(*schema.Set)
	authMethodsEventSourceLocations := common.ExpandStringList(authMethodsEventSourceLocationsSet.List())
	gatewaysEventSourceLocationsSet := d.Get("gateways_event_source_locations").(*schema.Set)
	gatewaysEventSourceLocations := common.ExpandStringList(gatewaysEventSourceLocationsSet.List())
	eventTypesSet := d.Get("event_types").(*schema.Set)
	eventTypes := common.ExpandStringList(eventTypesSet.List())
	key := d.Get("key").(string)
	url := d.Get("url").(string)
	serverCertificates := d.Get("server_certificates").(string)
	authType := d.Get("auth_type").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	authToken := d.Get("auth_token").(string)
	clientCertData := d.Get("client_cert_data").(string)
	privateKeyData := d.Get("private_key_data").(string)
	description := d.Get("description").(string)

	body := akeyless_api.EventForwarderUpdateWebhook{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ItemsEventSourceLocations, itemsEventSourceLocations)
	common.GetAkeylessPtr(&body.TargetsEventSourceLocations, targetsEventSourceLocations)
	common.GetAkeylessPtr(&body.AuthMethodsEventSourceLocations, authMethodsEventSourceLocations)
	common.GetAkeylessPtr(&body.GatewaysEventSourceLocations, gatewaysEventSourceLocations)
	common.GetAkeylessPtr(&body.EventTypes, eventTypes)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Url, url)
	common.GetAkeylessPtr(&body.ServerCertificates, serverCertificates)
	common.GetAkeylessPtr(&body.AuthType, authType)
	common.GetAkeylessPtr(&body.Username, username)
	common.GetAkeylessPtr(&body.Password, password)
	common.GetAkeylessPtr(&body.AuthToken, authToken)
	common.GetAkeylessPtr(&body.ClientCertData, clientCertData)
	common.GetAkeylessPtr(&body.PrivateKeyData, privateKeyData)
	common.GetAkeylessPtr(&body.Description, description)

	_, resp, err := client.EventForwarderUpdateWebhook(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update Event Forwarder Webhook", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceEventForwarderWebhookDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Id()

	body := akeyless_api.EventForwarderDelete{
		Token: &token,
		Name:  name,
	}

	ctx := context.Background()
	_, _, err := client.EventForwarderDelete(ctx).Body(body).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceEventForwarderWebhookImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	name := d.Id()

	err := resourceEventForwarderWebhookRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", name)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
