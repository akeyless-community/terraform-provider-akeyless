package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceKMIPServer() *schema.Resource {
	return &schema.Resource{
		Description: "KMIP server resource",
		Create:      resourceKMIPServerCreate,
		Read:        resourceKMIPServerRead,
		Update:      resourceKMIPServerUpdate,
		Delete:      resourceKMIPServerDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"hostname": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "KMIP server hostname",
			},
			"root": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Root path of the KMIP environment",
			},
			"certificate_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Default:     90,
				Description: "Server certificate TTL in days",
			},
			"expiration_event_in": {
				Type:        schema.TypeSet,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "How many days before certificate expiration to notify",
			},
			"active": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the KMIP server is active",
			},
		},
	}
}

func resourceKMIPServerCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	hostname := d.Get("hostname").(string)
	root := d.Get("root").(string)
	certificateTTL := int64(d.Get("certificate_ttl").(int))
	expirationEventIn := common.ExpandStringList(d.Get("expiration_event_in").(*schema.Set).List())

	body := akeyless_api.KmipServerSetup{
		Hostname: hostname,
		Root:     root,
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.CertificateTtl, certificateTTL)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)

	resp, res, err := client.KmipServerSetup(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create kmip server", res, err)
	}

	if resp != nil && resp.Root != nil && *resp.Root != "" {
		d.SetId(*resp.Root)
	} else {
		d.SetId(root)
	}

	return resourceKMIPServerRead(d, m)
}

func resourceKMIPServerRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	body := akeyless_api.KmipDescribeServer{
		Token: &token,
	}

	resp, res, err := client.KmipDescribeServer(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "failed to read kmip server", res, err)
	}

	if resp.Active != nil {
		if err := d.Set("active", *resp.Active); err != nil {
			return err
		}
	}
	if resp.Hostname != nil {
		if err := d.Set("hostname", *resp.Hostname); err != nil {
			return err
		}
	}
	if resp.Root != nil {
		if err := d.Set("root", *resp.Root); err != nil {
			return err
		}
	}
	if resp.ExpirationEvents != nil {
		if err := d.Set("expiration_event_in", common.ReadExpirationEventInParam(resp.ExpirationEvents)); err != nil {
			return err
		}
	}
	if resp.CertificateTtlInSeconds != nil {
		if ttl, ok := kmipDaysFromSeconds(*resp.CertificateTtlInSeconds); ok {
			if err := d.Set("certificate_ttl", ttl); err != nil {
				return err
			}
		}
	}

	if resp.Root != nil && *resp.Root != "" {
		d.SetId(*resp.Root)
	}

	return nil
}

func resourceKMIPServerUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	expirationEventIn := common.ExpandStringList(d.Get("expiration_event_in").(*schema.Set).List())

	body := akeyless_api.KmipServerUpdate{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)

	_, res, err := client.KmipServerUpdate(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update kmip server", res, err)
	}

	return resourceKMIPServerRead(d, m)
}

func resourceKMIPServerDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	body := akeyless_api.KmipDeleteServer{
		Token: &token,
	}

	if _, res, err := client.KmipDeleteServer(ctx).Body(body).Execute(); err != nil {
		return common.HandleError("failed to delete kmip server", res, err)
	}

	d.SetId("")
	return nil
}
