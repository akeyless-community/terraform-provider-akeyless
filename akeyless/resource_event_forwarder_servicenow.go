// generated file
package akeyless

import (
	"context"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
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
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("admin_pwd"), cty.GetAttrPath("admin_pwd_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("client_secret"), cty.GetAttrPath("client_secret_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("app_private_key_base64"), cty.GetAttrPath("app_private_key_base64_wo")),
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
			"gateways_event_source_locations": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Event sources",
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
			"admin_pwd_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "Workstation Admin Password (write-only, not stored in state). Requires Terraform 1.11+. Bump admin_pwd_wo_version to change it.",
			},
			"admin_pwd_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for admin_pwd_wo. Increment to update the value.",
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
			"client_secret_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "The client secret to use when connecting with jwt authentication (write-only, not stored in state). Requires Terraform 1.11+. Bump client_secret_wo_version to change it.",
			},
			"client_secret_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for client_secret_wo. Increment to update the value.",
			},
			"app_private_key_base64": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "The RSA Private Key to use when connecting with jwt authentication",
			},
			"app_private_key_base64_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "The RSA Private Key to use when connecting with jwt authentication (write-only, not stored in state). Requires Terraform 1.11+. Bump app_private_key_base64_wo_version to change it.",
			},
			"app_private_key_base64_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for app_private_key_base64_wo. Increment to update the value.",
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
	adminPwd, err := common.EffectiveSecretValue(d, "admin_pwd", "admin_pwd_wo")
	if err != nil {
		return err
	}
	userEmail := d.Get("user_email").(string)
	clientId := d.Get("client_id").(string)
	clientSecret, err := common.EffectiveSecretValue(d, "client_secret", "client_secret_wo")
	if err != nil {
		return err
	}
	appPrivateKeyBase64, err := common.EffectiveSecretValue(d, "app_private_key_base64", "app_private_key_base64_wo")
	if err != nil {
		return err
	}
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

	ctx := context.Background()

	name := d.Id()

	body := akeyless_api.EventForwarderGet{
		Name:  name,
		Token: &token,
	}

	readOut, res, err := client.EventForwarderGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get value", res, err)
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
	if rOut.IsEnabled != nil {
		err = d.Set("enable", fmt.Sprintf("%t", *rOut.IsEnabled))
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
	adminPwd, err := common.EffectiveSecretValue(d, "admin_pwd", "admin_pwd_wo")
	if err != nil {
		return err
	}
	userEmail := d.Get("user_email").(string)
	clientId := d.Get("client_id").(string)
	clientSecret, err := common.EffectiveSecretValue(d, "client_secret", "client_secret_wo")
	if err != nil {
		return err
	}
	appPrivateKeyBase64, err := common.EffectiveSecretValue(d, "app_private_key_base64", "app_private_key_base64_wo")
	if err != nil {
		return err
	}
	description := d.Get("description").(string)
	enable := d.Get("enable").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

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
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

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
