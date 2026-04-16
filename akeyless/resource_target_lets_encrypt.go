// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceLetsEncryptTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Let's Encrypt Target resource",
		Create:      resourceLetsEncryptTargetCreate,
		Read:        resourceLetsEncryptTargetRead,
		Update:      resourceLetsEncryptTargetUpdate,
		Delete:      resourceLetsEncryptTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceLetsEncryptTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"email": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Email address for ACME account registration",
			},
			"acme_challenge": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ACME challenge type. Options: [http/dns]",
				Default:     "http",
			},
			"dns_target_creds": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of existing cloud target for DNS credentials. Required when acme-challenge=dns. Supported: AWS, Azure, GCP targets",
			},
			"gcp_project": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GCP Cloud DNS: Project ID. Optional - can be derived from service account",
			},
			"hosted_zone": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS Route53 hosted zone ID. Required when dns-target-creds points to AWS target",
			},
			"lets_encrypt_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Let's Encrypt directory environment",
			},
			"resource_group": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure resource group name. Required when dns-target-creds points to Azure target",
			},
			"timeout": {
				Type:             schema.TypeString,
				Optional:         true,
				DiffSuppressFunc: common.DiffSuppressDuration,
				Description:      "Timeout for challenge validation",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that used to encrypt the target secret value (if empty, the account default protectionKey key will be used)",
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

func resourceLetsEncryptTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	email := d.Get("email").(string)
	acmeChallenge := d.Get("acme_challenge").(string)
	dnsTargetCreds := d.Get("dns_target_creds").(string)
	gcpProject := d.Get("gcp_project").(string)
	hostedZone := d.Get("hosted_zone").(string)
	letsEncryptUrl := d.Get("lets_encrypt_url").(string)
	resourceGroup := d.Get("resource_group").(string)
	timeout := d.Get("timeout").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.TargetCreateLetsEncrypt{
		Name:  name,
		Email: email,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AcmeChallenge, acmeChallenge)
	common.GetAkeylessPtr(&body.DnsTargetCreds, dnsTargetCreds)
	common.GetAkeylessPtr(&body.GcpProject, gcpProject)
	common.GetAkeylessPtr(&body.HostedZone, hostedZone)
	common.GetAkeylessPtr(&body.LetsEncryptUrl, letsEncryptUrl)
	common.GetAkeylessPtr(&body.ResourceGroup, resourceGroup)
	common.GetAkeylessPtr(&body.Timeout, timeout)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.TargetCreateLetsEncrypt(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceLetsEncryptTargetRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.Value != nil && rOut.Value.LetsencryptTargetDetails != nil {
		details := rOut.Value.LetsencryptTargetDetails
		if details.Email != nil {
			err = d.Set("email", *details.Email)
			if err != nil {
				return err
			}
		}
		if details.ChallengeType != nil {
			err = d.Set("acme_challenge", *details.ChallengeType)
			if err != nil {
				return err
			}
		}
		if details.DnsTargetName != nil {
			err = d.Set("dns_target_creds", *details.DnsTargetName)
			if err != nil {
				return err
			}
		}
		if details.GcpProject != nil {
			err = d.Set("gcp_project", *details.GcpProject)
			if err != nil {
				return err
			}
		}
		if details.HostedZone != nil {
			err = d.Set("hosted_zone", *details.HostedZone)
			if err != nil {
				return err
			}
		}
		if details.AcmeEnvironment != nil {
			err = d.Set("lets_encrypt_url", *details.AcmeEnvironment)
			if err != nil {
				return err
			}
		}
		if details.ResourceGroup != nil {
			err = d.Set("resource_group", *details.ResourceGroup)
			if err != nil {
				return err
			}
		}
		if details.Timeout != nil {
			timeout := *details.Timeout
			duration := common.ConvertNanoSecondsIntoDurationString(timeout)
			err = d.Set("timeout", duration)
			if err != nil {
				return err
			}
		}
	}

	if rOut.Target != nil {
		if rOut.Target.Comment != nil {
			err = d.Set("description", *rOut.Target.Comment)
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
	}

	d.SetId(path)

	return nil
}

func resourceLetsEncryptTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	email := d.Get("email").(string)
	acmeChallenge := d.Get("acme_challenge").(string)
	dnsTargetCreds := d.Get("dns_target_creds").(string)
	gcpProject := d.Get("gcp_project").(string)
	hostedZone := d.Get("hosted_zone").(string)
	letsEncryptUrl := d.Get("lets_encrypt_url").(string)
	resourceGroup := d.Get("resource_group").(string)
	timeout := d.Get("timeout").(string)
	description := d.Get("description").(string)
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.TargetUpdateLetsEncrypt{
		Name:  name,
		Email: email,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.NewName, name)
	common.GetAkeylessPtr(&body.AcmeChallenge, acmeChallenge)
	common.GetAkeylessPtr(&body.DnsTargetCreds, dnsTargetCreds)
	common.GetAkeylessPtr(&body.GcpProject, gcpProject)
	common.GetAkeylessPtr(&body.HostedZone, hostedZone)
	common.GetAkeylessPtr(&body.LetsEncryptUrl, letsEncryptUrl)
	common.GetAkeylessPtr(&body.ResourceGroup, resourceGroup)
	common.GetAkeylessPtr(&body.Timeout, timeout)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.TargetUpdateLetsEncrypt(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceLetsEncryptTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceLetsEncryptTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceLetsEncryptTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
