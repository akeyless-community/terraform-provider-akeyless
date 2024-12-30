// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceWindowsTarget() *schema.Resource {
	return &schema.Resource{
		Description: "windows Target resource",
		Create:      resourceWindowsTargetCreate,
		Read:        resourceWindowsTargetRead,
		Update:      resourceWindowsTargetUpdate,
		Delete:      resourceWindowsTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceWindowsTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"hostname": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "server hostname or IP Address",
			},
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Privileged username",
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Privileged user password",
			},
			"domain": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User domain name",
			},
			"port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Server WinRM port",
				Default:     "5986",
			},
			"use_tls": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable TLS for WinRM over HTTPS [true/false]",
				Default:     "true",
			},
			"certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "SSL CA certificate in base64 encoding generated from a trusted Certificate Authority (CA)",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Key name. The key is used to encrypt the target secret value. If the key name is not specified, the account default protection key is used",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
		},
	}
}

func resourceWindowsTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	hostname := d.Get("hostname").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	domain := d.Get("domain").(string)
	port := d.Get("port").(string)
	useTls := d.Get("use_tls").(string)
	certificate := d.Get("certificate").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetCreateWindows{
		Name:     name,
		Hostname: hostname,
		Username: username,
		Password: password,
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.Domain, domain)
	common.GetAkeylessPtr(&body.Port, port)
	common.GetAkeylessPtr(&body.UseTls, useTls)
	common.GetAkeylessPtr(&body.Certificate, certificate)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.TargetCreateWindows(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceWindowsTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
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
	if rOut.Value.WindowsTargetDetails.Hostname != nil {
		err = d.Set("hostname", *rOut.Value.WindowsTargetDetails.Hostname)
		if err != nil {
			return err
		}
	}
	if rOut.Value.WindowsTargetDetails.Username != nil {
		err = d.Set("username", *rOut.Value.WindowsTargetDetails.Username)
		if err != nil {
			return err
		}
	}
	if rOut.Value.WindowsTargetDetails.Password != nil {
		err = d.Set("password", *rOut.Value.WindowsTargetDetails.Password)
		if err != nil {
			return err
		}
	}
	if rOut.Value.WindowsTargetDetails.DomainName != nil {
		err = d.Set("domain", *rOut.Value.WindowsTargetDetails.DomainName)
		if err != nil {
			return err
		}
	}
	if rOut.Value.WindowsTargetDetails.Port != nil {
		err = d.Set("port", *rOut.Value.WindowsTargetDetails.Port)
		if err != nil {
			return err
		}
	}
	if rOut.Value.WindowsTargetDetails.UseTls != nil {
		err = d.Set("use_tls", strconv.FormatBool(*rOut.Value.WindowsTargetDetails.UseTls))
		if err != nil {
			return err
		}
	}
	if rOut.Value.WindowsTargetDetails.Certificate != nil {
		err = d.Set("certificate", *rOut.Value.WindowsTargetDetails.Certificate)
		if err != nil {
			return err
		}
	}
	if rOut.Target.ProtectionKeyName != nil {
		err = d.Set("key", *rOut.Target.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.Target.Comment != nil {
		err = d.Set("description", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceWindowsTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	hostname := d.Get("hostname").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	domain := d.Get("domain").(string)
	port := d.Get("port").(string)
	useTls := d.Get("use_tls").(string)
	certificate := d.Get("certificate").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetUpdateWindows{
		Name:     name,
		Hostname: hostname,
		Username: username,
		Password: password,
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.Domain, domain)
	common.GetAkeylessPtr(&body.Port, port)
	common.GetAkeylessPtr(&body.UseTls, useTls)
	common.GetAkeylessPtr(&body.Certificate, certificate)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.TargetUpdateWindows(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceWindowsTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.TargetDelete{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.TargetDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceWindowsTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()

	err := resourceWindowsTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
