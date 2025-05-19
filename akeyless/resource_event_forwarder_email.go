// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceEventForwarderEmail() *schema.Resource {
	return &schema.Resource{
		Description: "Event Forwarder Email resource",
		Create:      resourceEventForwarderEmailCreate,
		Read:        resourceEventForwarderEmailRead,
		Update:      resourceEventForwarderEmailUpdate,
		Delete:      resourceEventForwarderEmailDelete,
		Importer: &schema.ResourceImporter{
			State: resourceEventForwarderEmailImport,
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
				Description: "A comma-separated list of types of events to notify about",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Key name. The key will be used to encrypt the Event Forwarder secret value. If key name is not specified, the account default protection key is used",
			},
			"email_to": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma seperated list of email addresses to send event to",
			},
			"override_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Override Akeyless default URL with your Gateway url (port 18888)",
			},
			"include_error": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set this option to include event errors details [true/false]",
			},
			"runner_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Event Forwarder runner type [immediate/periodic]",
				Default:     "immediate",
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
		},
	}
}

func resourceEventForwarderEmailCreate(d *schema.ResourceData, m interface{}) error {
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
	emailTo := d.Get("email_to").(string)
	overrideUrl := d.Get("override_url").(string)
	includeError := d.Get("include_error").(string)
	runnerType := d.Get("runner_type").(string)
	every := d.Get("every").(string)
	description := d.Get("description").(string)

	body := akeyless_api.EventForwarderCreateEmail{
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
	common.GetAkeylessPtr(&body.EmailTo, emailTo)
	common.GetAkeylessPtr(&body.OverrideUrl, overrideUrl)
	common.GetAkeylessPtr(&body.IncludeError, includeError)
	common.GetAkeylessPtr(&body.Every, every)
	common.GetAkeylessPtr(&body.Description, description)

	_, resp, err := client.EventForwarderCreateEmail(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Event Forwarder Email", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceEventForwarderEmailRead(d *schema.ResourceData, m interface{}) error {
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
		if *rOut.NotiForwarderType != common.EventForwarderEmail {
			return fmt.Errorf("resource type is not email")
		}
	}

	err = common.SetCommonEventForwarderVars(d, rOut)
	if err != nil {
		return err
	}

	if rOut.ToEmails != nil {
		emails := make([]string, len(rOut.ToEmails))
		for _, email := range rOut.ToEmails {
			if email.ToEmail != nil {
				emails = append(emails, *email.ToEmail)
			}
		}
		emailTo := strings.Join(emails, ",")
		err = d.Set("email_to", emailTo)
		if err != nil {
			return err
		}
	}
	if rOut.OverrideUrl != nil {
		err = d.Set("override_url", *rOut.OverrideUrl)
		if err != nil {
			return err
		}
	}
	if rOut.IncludeError != nil {
		err = d.Set("include_error", strconv.FormatBool(*rOut.IncludeError))
		if err != nil {
			return err
		}
	}

	d.SetId(name)

	return nil
}

func resourceEventForwarderEmailUpdate(d *schema.ResourceData, m interface{}) error {

	err := common.ValidateEventForwarderUpdateParams(d)
	if err != nil {
		return fmt.Errorf("failed to update: %w", err)
	}

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
	emailTo := d.Get("email_to").(string)
	overrideUrl := d.Get("override_url").(string)
	includeError := d.Get("include_error").(string)
	description := d.Get("description").(string)

	body := akeyless_api.EventForwarderUpdateEmail{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ItemsEventSourceLocations, itemsEventSourceLocations)
	common.GetAkeylessPtr(&body.TargetsEventSourceLocations, targetsEventSourceLocations)
	common.GetAkeylessPtr(&body.AuthMethodsEventSourceLocations, authMethodsEventSourceLocations)
	common.GetAkeylessPtr(&body.GatewaysEventSourceLocations, gatewaysEventSourceLocations)
	common.GetAkeylessPtr(&body.EventTypes, eventTypes)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.EmailTo, emailTo)
	common.GetAkeylessPtr(&body.OverrideUrl, overrideUrl)
	common.GetAkeylessPtr(&body.IncludeError, includeError)
	common.GetAkeylessPtr(&body.Description, description)

	_, resp, err := client.EventForwarderUpdateEmail(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update Event Forwarder Email", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceEventForwarderEmailDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	body := akeyless_api.EventForwarderDelete{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.EventForwarderDelete(ctx).Body(body).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceEventForwarderEmailImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	name := d.Id()

	err := resourceEventForwarderEmailRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", name)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
