package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceEventForwarderTeams() *schema.Resource {
	return &schema.Resource{
		Description: "Event Forwarder Microsoft Teams resource",
		Create:      resourceEventForwarderTeamsCreate,
		Read:        resourceEventForwarderTeamsRead,
		Update:      resourceEventForwarderTeamsUpdate,
		Delete:      resourceEventForwarderTeamsDelete,
		Importer: &schema.ResourceImporter{
			State: resourceEventForwarderTeamsImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "EventForwarder name",
				ForceNew:    true,
			},
			"url": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Teams Webhook URL",
			},
			"gateway_event_source_locations": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "Event sources",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"items_event_source_locations": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Items Event sources",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"targets_event_source_locations": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Targets Event sources",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"auth_methods_event_source_locations": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Auth Method Event sources",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"event_types": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of event types to notify about [request-access, certificate-pending-expiration, certificate-expired, certificate-provisioning-success, certificate-provisioning-failure, auth-method-pending-expiration, auth-method-expired, next-automatic-rotation, rotated-secret-success, rotated-secret-failure, dynamic-secret-failure, multi-auth-failure, uid-rotation-failure, apply-justification, email-auth-method-approved, usage, rotation-usage, gateway-inactive, static-secret-updated, rate-limiting, usage-report, secret-sync]",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that used to encrypt the EventForwarder secret value (if empty, the account default protectionKey key will be used)",
			},
			"runner_type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Event Forwarder runner type [immediate/periodic]",
			},
			"every": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Rate of periodic runner repetition in hours",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable Event Forwarder [true/false]",
				Default:     "true",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceEventForwarderTeamsCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	url := d.Get("url").(string)
	gatewayEventSourceLocationsSet := d.Get("gateway_event_source_locations").(*schema.Set)
	gatewayEventSourceLocations := common.ExpandStringList(gatewayEventSourceLocationsSet.List())
	itemsEventSourceLocationsSet := d.Get("items_event_source_locations").(*schema.Set)
	itemsEventSourceLocations := common.ExpandStringList(itemsEventSourceLocationsSet.List())
	targetsEventSourceLocationsSet := d.Get("targets_event_source_locations").(*schema.Set)
	targetsEventSourceLocations := common.ExpandStringList(targetsEventSourceLocationsSet.List())
	authMethodsEventSourceLocationsSet := d.Get("auth_methods_event_source_locations").(*schema.Set)
	authMethodsEventSourceLocations := common.ExpandStringList(authMethodsEventSourceLocationsSet.List())
	eventTypesSet := d.Get("event_types").(*schema.Set)
	eventTypes := common.ExpandStringList(eventTypesSet.List())
	key := d.Get("key").(string)
	runnerType := d.Get("runner_type").(string)
	every := d.Get("every").(string)
	description := d.Get("description").(string)

	body := akeyless_api.EventForwarderCreateTeams{
		Name:                         name,
		Url:                          url,
		GatewaysEventSourceLocations: gatewayEventSourceLocations,
		RunnerType:                   runnerType,
		Token:                        &token,
	}
	common.GetAkeylessPtr(&body.ItemsEventSourceLocations, itemsEventSourceLocations)
	common.GetAkeylessPtr(&body.TargetsEventSourceLocations, targetsEventSourceLocations)
	common.GetAkeylessPtr(&body.AuthMethodsEventSourceLocations, authMethodsEventSourceLocations)
	common.GetAkeylessPtr(&body.EventTypes, eventTypes)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Every, every)
	common.GetAkeylessPtr(&body.Description, description)

	_, resp, err := client.EventForwarderCreateTeams(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Event Forwarder Teams", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceEventForwarderTeamsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.EventForwarderGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.EventForwarderGet(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("failed to get event forwarder: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to get event forwarder: %w", err)
	}

	if rOut.EventForwarderDetails != nil {
		if rOut.EventForwarderDetails.TeamsNotiForwarderDetails != nil {
			if rOut.EventForwarderDetails.TeamsNotiForwarderDetails.WebhookUrl != nil {
				err = d.Set("url", *rOut.EventForwarderDetails.TeamsNotiForwarderDetails.WebhookUrl)
				if err != nil {
					return err
				}
			}
		}
	}

	if rOut.EventForwarder != nil {
		if rOut.EventForwarder.EventTypes != nil {
			err = d.Set("event_types", rOut.EventForwarder.EventTypes)
			if err != nil {
				return err
			}
		}
		if rOut.EventForwarder.RunnerType != nil {
			err = d.Set("runner_type", *rOut.EventForwarder.RunnerType)
			if err != nil {
				return err
			}
		}
		if rOut.EventForwarder.ProtectionKey != nil {
			err = d.Set("key", *rOut.EventForwarder.ProtectionKey)
			if err != nil {
				return err
			}
		}
		if rOut.EventForwarder.Comment != nil {
			err = d.Set("description", *rOut.EventForwarder.Comment)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceEventForwarderTeamsUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	url := d.Get("url").(string)
	gatewayEventSourceLocationsSet := d.Get("gateway_event_source_locations").(*schema.Set)
	gatewayEventSourceLocations := common.ExpandStringList(gatewayEventSourceLocationsSet.List())
	itemsEventSourceLocationsSet := d.Get("items_event_source_locations").(*schema.Set)
	itemsEventSourceLocations := common.ExpandStringList(itemsEventSourceLocationsSet.List())
	targetsEventSourceLocationsSet := d.Get("targets_event_source_locations").(*schema.Set)
	targetsEventSourceLocations := common.ExpandStringList(targetsEventSourceLocationsSet.List())
	authMethodsEventSourceLocationsSet := d.Get("auth_methods_event_source_locations").(*schema.Set)
	authMethodsEventSourceLocations := common.ExpandStringList(authMethodsEventSourceLocationsSet.List())
	eventTypesSet := d.Get("event_types").(*schema.Set)
	eventTypes := common.ExpandStringList(eventTypesSet.List())
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	enable := d.Get("enable").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.EventForwarderUpdateTeams{
		Name:                         name,
		Url:                          url,
		GatewaysEventSourceLocations: gatewayEventSourceLocations,
		Token:                        &token,
	}
	common.GetAkeylessPtr(&body.ItemsEventSourceLocations, itemsEventSourceLocations)
	common.GetAkeylessPtr(&body.TargetsEventSourceLocations, targetsEventSourceLocations)
	common.GetAkeylessPtr(&body.AuthMethodsEventSourceLocations, authMethodsEventSourceLocations)
	common.GetAkeylessPtr(&body.EventTypes, eventTypes)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.EventForwarderUpdateTeams(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update Event Forwarder Teams", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceEventForwarderTeamsDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.EventForwarderDelete{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, resp, err := client.EventForwarderDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return common.HandleError("can't delete Event Forwarder Teams", resp, err)
	}

	return nil
}

func resourceEventForwarderTeamsImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceEventForwarderTeamsRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
