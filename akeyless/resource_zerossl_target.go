// generated fule
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

func resourceZerosslTarget() *schema.Resource {
	return &schema.Resource{
		Description: "ZeroSSL Target resource",
		Create:      resourceZerosslTargetCreate,
		Read:        resourceZerosslTargetRead,
		Update:      resourceZerosslTargetUpdate,
		Delete:      resourceZerosslTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceZerosslTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"api_key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "API Key of the ZeroSSLTarget account",
			},
			"imap_username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Username to access the IMAP service",
			},
			"imap_password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Password to access the IMAP service",
			},
			"imap_fqdn": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "FQDN of the IMAP service",
			},
			"imap_target_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Email to use when asking ZeroSSL to send a validation email, if empty will use username",
			},
			"imap_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Port of the IMAP service",
				Default:     "993",
			},
			"timeout": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Timeout waiting for certificate validation",
				Default:     "5m",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
		},
	}
}

func resourceZerosslTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	apiKey := d.Get("api_key").(string)
	imapUsername := d.Get("imap_username").(string)
	imapPassword := d.Get("imap_password").(string)
	imapFqdn := d.Get("imap_fqdn").(string)
	imapTargetEmail := d.Get("imap_target_email").(string)
	imapPort := d.Get("imap_port").(string)
	timeout := d.Get("timeout").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetCreateZeroSSL{
		Name:         name,
		ApiKey:       apiKey,
		ImapUsername: imapUsername,
		ImapPassword: imapPassword,
		ImapFqdn:     imapFqdn,
		Token:        &token,
	}
	common.GetAkeylessPtr(&body.Timeout, timeout)
	common.GetAkeylessPtr(&body.ImapTargetEmail, imapTargetEmail)
	common.GetAkeylessPtr(&body.ImapPort, imapPort)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.TargetCreateZeroSSL(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("failed to create target: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to create target: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceZerosslTargetRead(d *schema.ResourceData, m interface{}) error {
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
			return fmt.Errorf("failed to get target details: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to get target details: %v", err)
	}

	if rOut.Value != nil {
		targetDetails := *rOut.Value

		if targetDetails.ZerosslTargetDetails.ApiKey != nil {
			err := d.Set("api_key", *targetDetails.ZerosslTargetDetails.ApiKey)
			if err != nil {
				return err
			}
		}
		if targetDetails.ZerosslTargetDetails.Timeout != nil {
			timeout := *targetDetails.ZerosslTargetDetails.Timeout
			duration := common.ConvertNanoSecondsIntoDurationString(timeout)

			err := d.Set("timeout", duration)
			if err != nil {
				return err
			}
		}
		if targetDetails.ZerosslTargetDetails.ImapUser != nil {
			err := d.Set("imap_username", *targetDetails.ZerosslTargetDetails.ImapUser)
			if err != nil {
				return err
			}
		}
		if targetDetails.ZerosslTargetDetails.ImapPassword != nil {
			err := d.Set("imap_password", *targetDetails.ZerosslTargetDetails.ImapPassword)
			if err != nil {
				return err
			}
		}
		if targetDetails.ZerosslTargetDetails.ImapFqdn != nil {
			err := d.Set("imap_fqdn", *targetDetails.ZerosslTargetDetails.ImapFqdn)
			if err != nil {
				return err
			}
		}
		if targetDetails.ZerosslTargetDetails.ValidationEmail != nil {
			err := d.Set("imap_target_email", *targetDetails.ZerosslTargetDetails.ValidationEmail)
			if err != nil {
				return err
			}
		}
		if targetDetails.ZerosslTargetDetails.ImapPort != nil {
			err := d.Set("imap_port", *targetDetails.ZerosslTargetDetails.ImapPort)
			if err != nil {
				return err
			}
		}
	}

	if rOut.Target != nil {
		target := *rOut.Target

		if target.Comment != nil {
			err := d.Set("description", *target.Comment)
			if err != nil {
				return err
			}
		}
		if target.ProtectionKeyName != nil {
			err = d.Set("key", *target.ProtectionKeyName)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceZerosslTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	apiKey := d.Get("api_key").(string)
	imapUsername := d.Get("imap_username").(string)
	imapPassword := d.Get("imap_password").(string)
	imapFqdn := d.Get("imap_fqdn").(string)
	imapTargetEmail := d.Get("imap_target_email").(string)
	imapPort := d.Get("imap_port").(string)
	timeout := d.Get("timeout").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetUpdateZeroSSL{
		Name:         name,
		ApiKey:       apiKey,
		ImapUsername: imapUsername,
		ImapPassword: imapPassword,
		ImapFqdn:     imapFqdn,
		Token:        &token,
	}
	common.GetAkeylessPtr(&body.Timeout, timeout)
	common.GetAkeylessPtr(&body.ImapTargetEmail, imapTargetEmail)
	common.GetAkeylessPtr(&body.ImapPort, imapPort)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.TargetUpdateZeroSSL(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("failed to update target: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to update target: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceZerosslTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceZerosslTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceZerosslTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
