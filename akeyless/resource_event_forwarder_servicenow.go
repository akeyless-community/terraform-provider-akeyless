// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceEventForwarderServiceNow() *schema.Resource {
	return &schema.Resource{
		Description: "Event Forwarder Service Now resource",
		Create:      resourceEventForwarderServiceNowCreate,
		Read:        resourceEventForwarderServiceNowRead,
		Update:      resourceEventForwarderServiceNowUpdate,
		Delete:      resourceEventForwarderServiceNowDelete,
		Importer: &schema.ResourceImporter{
			State: resourceEventForwarderServiceNowImport,
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
			"host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Workstation Host",
			},
			"auth_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The authentication type to use [user-pass/jwt]",
				Default:     "user-pass",
			},
			"admin_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Workstation Admin Name",
			},
			"admin_pwd": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Workstation Admin Password",
			},
			"user_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The user email to identify with when connecting with jwt authentication",
			},
			"client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The client ID to use when connecting with jwt authentication",
			},
			"client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "The client secret to use when connecting with jwt authentication",
			},
			"app_private_key_base64": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "The RSA Private Key to use when connecting with jwt authentication",
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

func resourceEventForwarderServiceNowCreate(d *schema.ResourceData, m interface{}) error {
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
	host := d.Get("host").(string)
	authType := d.Get("auth_type").(string)
	adminName := d.Get("admin_name").(string)
	adminPwd := d.Get("admin_pwd").(string)
	userEmail := d.Get("user_email").(string)
	clientId := d.Get("client_id").(string)
	clientSecret := d.Get("client_secret").(string)
	appPrivateKeyBase64 := d.Get("app_private_key_base64").(string)
	runnerType := d.Get("runner_type").(string)
	every := d.Get("every").(string)
	description := d.Get("description").(string)

	body := akeyless_api.EventForwarderCreateServiceNow{
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
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.AuthType, authType)
	common.GetAkeylessPtr(&body.AdminName, adminName)
	common.GetAkeylessPtr(&body.AdminPwd, adminPwd)
	common.GetAkeylessPtr(&body.UserEmail, userEmail)
	common.GetAkeylessPtr(&body.ClientId, clientId)
	common.GetAkeylessPtr(&body.ClientSecret, clientSecret)
	common.GetAkeylessPtr(&body.AppPrivateKeyBase64, appPrivateKeyBase64)
	common.GetAkeylessPtr(&body.Every, every)
	common.GetAkeylessPtr(&body.Description, description)

	_, resp, err := client.EventForwarderCreateServiceNow(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Event Forwarder Service Now", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceEventForwarderServiceNowRead(d *schema.ResourceData, m interface{}) error {
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
		if *rOut.NotiForwarderType != common.EventForwarderServiceNow {
			return fmt.Errorf("resource type is not servicenow")
		}
	}

	err = common.SetCommonEventForwarderVars(d, rOut)
	if err != nil {
		return err
	}

	if rOut.Endpoint != nil {
		err = d.Set("host", *rOut.Endpoint)
		if err != nil {
			return err
		}
	}
	if rOut.AuthType != nil {
		err = d.Set("auth_type", *rOut.AuthType)
		if err != nil {
			return err
		}
	}
	if rOut.Username != nil {
		err = d.Set("admin_name", *rOut.Username)
		if err != nil {
			return err
		}
	}
	if rOut.UserEmail != nil {
		err = d.Set("user_email", *rOut.UserEmail)
		if err != nil {
			return err
		}
	}
	if rOut.ClientId != nil {
		err = d.Set("client_id", *rOut.ClientId)
		if err != nil {
			return err
		}
	}

	d.SetId(name)

	return nil
}

func resourceEventForwarderServiceNowUpdate(d *schema.ResourceData, m interface{}) error {

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
	host := d.Get("host").(string)
	authType := d.Get("auth_type").(string)
	adminName := d.Get("admin_name").(string)
	adminPwd := d.Get("admin_pwd").(string)
	userEmail := d.Get("user_email").(string)
	clientId := d.Get("client_id").(string)
	clientSecret := d.Get("client_secret").(string)
	appPrivateKeyBase64 := d.Get("app_private_key_base64").(string)
	description := d.Get("description").(string)

	body := akeyless_api.EventForwarderUpdateServiceNow{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ItemsEventSourceLocations, itemsEventSourceLocations)
	common.GetAkeylessPtr(&body.TargetsEventSourceLocations, targetsEventSourceLocations)
	common.GetAkeylessPtr(&body.AuthMethodsEventSourceLocations, authMethodsEventSourceLocations)
	common.GetAkeylessPtr(&body.GatewaysEventSourceLocations, gatewaysEventSourceLocations)
	common.GetAkeylessPtr(&body.EventTypes, eventTypes)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.AuthType, authType)
	common.GetAkeylessPtr(&body.AdminName, adminName)
	common.GetAkeylessPtr(&body.AdminPwd, adminPwd)
	common.GetAkeylessPtr(&body.UserEmail, userEmail)
	common.GetAkeylessPtr(&body.ClientId, clientId)
	common.GetAkeylessPtr(&body.ClientSecret, clientSecret)
	common.GetAkeylessPtr(&body.AppPrivateKeyBase64, appPrivateKeyBase64)
	common.GetAkeylessPtr(&body.Description, description)

	_, resp, err := client.EventForwarderUpdateServiceNow(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update Event Forwarder ServiceNow", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceEventForwarderServiceNowDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceEventForwarderServiceNowImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	name := d.Id()

	err := resourceEventForwarderServiceNowRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", name)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
