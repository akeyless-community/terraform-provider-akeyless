package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGodaddyTarget() *schema.Resource {
	return &schema.Resource{
		Description: "GoDaddy Target resource",
		Create:      resourceGodaddyTargetCreate,
		Read:        resourceGodaddyTargetRead,
		Update:      resourceGodaddyTargetUpdate,
		Delete:      resourceGodaddyTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGodaddyTargetImport,
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
				Description: "Key of the api credentials to the Godaddy account",
			},
			"secret": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Secret of the api credentials to the Godaddy account",
			},
			"imap_fqdn": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ImapFQDN of the IMAP service, FQDN or IPv4 address. Must be FQDN if the IMAP is using TLS",
			},
			"imap_username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ImapUsername to access the IMAP service",
			},
			"imap_password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "ImapPassword to access the IMAP service",
			},
			"imap_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ImapPort of the IMAP service",
				Default:     "993",
			},
			"customer_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customer ID (ShopperId) required for renewal of imported certificates",
			},
			"timeout": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Timeout waiting for certificate validation in Duration format (1h - 1 Hour, 20m - 20 Minutes, 33m3s - 33 Minutes and 3 Seconds), maximum 1h.",
				Default:          "5m",
				DiffSuppressFunc: common.DiffSuppressDuration,
			},
			"validation_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Email address for certificate validation",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that used to encrypt the target secret value (if empty, the account default protectionKey key will be used)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceGodaddyTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	apiKey := d.Get("api_key").(string)
	secret := d.Get("secret").(string)
	imapFqdn := d.Get("imap_fqdn").(string)
	imapUsername := d.Get("imap_username").(string)
	imapPassword := d.Get("imap_password").(string)
	imapPort := d.Get("imap_port").(string)
	customerId := d.Get("customer_id").(string)
	timeout := d.Get("timeout").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.CreateGodaddyTarget{
		Name:         name,
		ApiKey:       apiKey,
		Secret:       secret,
		ImapFqdn:     imapFqdn,
		ImapUsername: imapUsername,
		ImapPassword: imapPassword,
		Token:        &token,
	}
	common.GetAkeylessPtr(&body.ImapPort, imapPort)
	common.GetAkeylessPtr(&body.CustomerId, customerId)
	common.GetAkeylessPtr(&body.Timeout, timeout)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.CreateGodaddyTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceGodaddyTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "failed to get target details", res, err)
	}

	if rOut.Value != nil {
		targetDetails := *rOut.Value

		if targetDetails.GodaddyTargetDetails != nil {
			if targetDetails.GodaddyTargetDetails.Key != nil {
				err := d.Set("api_key", *targetDetails.GodaddyTargetDetails.Key)
				if err != nil {
					return err
				}
			}
			if targetDetails.GodaddyTargetDetails.Secret != nil {
				err := d.Set("secret", *targetDetails.GodaddyTargetDetails.Secret)
				if err != nil {
					return err
				}
			}
			if targetDetails.GodaddyTargetDetails.ImapFqdn != nil {
				err := d.Set("imap_fqdn", *targetDetails.GodaddyTargetDetails.ImapFqdn)
				if err != nil {
					return err
				}
			}
			if targetDetails.GodaddyTargetDetails.ImapUser != nil {
				err := d.Set("imap_username", *targetDetails.GodaddyTargetDetails.ImapUser)
				if err != nil {
					return err
				}
			}
			if targetDetails.GodaddyTargetDetails.ImapPassword != nil {
				err := d.Set("imap_password", *targetDetails.GodaddyTargetDetails.ImapPassword)
				if err != nil {
					return err
				}
			}
			if targetDetails.GodaddyTargetDetails.ImapPort != nil {
				err := d.Set("imap_port", *targetDetails.GodaddyTargetDetails.ImapPort)
				if err != nil {
					return err
				}
			}
			if targetDetails.GodaddyTargetDetails.ShopperId != nil {
				err := d.Set("customer_id", *targetDetails.GodaddyTargetDetails.ShopperId)
				if err != nil {
					return err
				}
			}
			if targetDetails.GodaddyTargetDetails.Timeout != nil {
				timeout := *targetDetails.GodaddyTargetDetails.Timeout
				duration := common.ConvertNanoSecondsIntoDurationString(timeout)
				err := d.Set("timeout", duration)
				if err != nil {
					return err
				}
			}
			if targetDetails.GodaddyTargetDetails.ValidationEmail != nil {
				err := d.Set("validation_email", *targetDetails.GodaddyTargetDetails.ValidationEmail)
				if err != nil {
					return err
				}
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

func resourceGodaddyTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	apiKey := d.Get("api_key").(string)
	secret := d.Get("secret").(string)
	imapFqdn := d.Get("imap_fqdn").(string)
	imapUsername := d.Get("imap_username").(string)
	imapPassword := d.Get("imap_password").(string)
	imapPort := d.Get("imap_port").(string)
	customerId := d.Get("customer_id").(string)
	timeout := d.Get("timeout").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.UpdateGodaddyTarget{
		Name:         name,
		ApiKey:       apiKey,
		Secret:       secret,
		ImapFqdn:     imapFqdn,
		ImapUsername: imapUsername,
		ImapPassword: imapPassword,
		Token:        &token,
	}
	common.GetAkeylessPtr(&body.ImapPort, imapPort)
	common.GetAkeylessPtr(&body.CustomerId, customerId)
	common.GetAkeylessPtr(&body.Timeout, timeout)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.UpdateGodaddyTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceGodaddyTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceGodaddyTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceGodaddyTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
