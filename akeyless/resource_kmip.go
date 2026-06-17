package akeyless

import (
	"context"
	"strconv"

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

func resourceKMIPClient() *schema.Resource {
	return &schema.Resource{
		Description: "KMIP client resource",
		Create:      resourceKMIPClientCreate,
		Read:        resourceKMIPClientRead,
		Update:      resourceKMIPClientUpdate,
		Delete:      resourceKMIPClientDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Client name",
			},
			"client_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Server-generated client identifier",
			},
			"activate_keys_on_creation": {
				Type:        schema.TypeBool,
				Optional:    true,
				ForceNew:    true,
				Default:     false,
				Description: "Whether newly created keys on the client should be active",
			},
			"certificate_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Default:     90,
				Description: "Client certificate TTL in days",
			},
			"expiration_event_in": {
				Type:        schema.TypeSet,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "How many days before certificate expiration to notify",
			},
			"certificate": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Client certificate returned on creation",
			},
			"key": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Client private key returned on creation",
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

func resourceKMIPClientCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	activateKeysOnCreation := strconv.FormatBool(d.Get("activate_keys_on_creation").(bool))
	certificateTTL := int64(d.Get("certificate_ttl").(int))
	expirationEventIn := common.ExpandStringList(d.Get("expiration_event_in").(*schema.Set).List())

	body := akeyless_api.KmipCreateClient{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.ActivateKeysOnCreation, activateKeysOnCreation)
	common.GetAkeylessPtr(&body.CertificateTtl, certificateTTL)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)

	resp, res, err := client.KmipCreateClient(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create kmip client", res, err)
	}

	if resp != nil && resp.Id != nil && *resp.Id != "" {
		if err := d.Set("client_id", *resp.Id); err != nil {
			return err
		}
		d.SetId(*resp.Id)
	}
	if resp != nil && resp.Certificate != nil {
		if err := d.Set("certificate", *resp.Certificate); err != nil {
			return err
		}
	}
	if resp != nil && resp.Key != nil {
		if err := d.Set("key", *resp.Key); err != nil {
			return err
		}
	}

	return resourceKMIPClientRead(d, m)
}

func resourceKMIPClientRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	body := akeyless_api.KmipListClients{
		Token: &token,
	}

	resp, res, err := client.KmipListClients(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "failed to read kmip client", res, err)
	}

	matchID := d.Id()
	matchName := d.Get("name").(string)
	for _, item := range resp.Clients {
		if item.Id != nil && *item.Id == matchID {
			return kmipSetClientState(d, &item)
		}
		if matchID == "" && item.Name != nil && *item.Name == matchName {
			return kmipSetClientState(d, &item)
		}
	}

	d.SetId("")
	return nil
}

func resourceKMIPClientUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	clientID := d.Get("client_id").(string)
	name := d.Get("name").(string)
	expirationEventIn := common.ExpandStringList(d.Get("expiration_event_in").(*schema.Set).List())

	body := akeyless_api.KmipClientUpdate{
		ClientId: &clientID,
		Name:     &name,
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)

	_, res, err := client.KmipClientUpdate(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update kmip client", res, err)
	}

	return resourceKMIPClientRead(d, m)
}

func resourceKMIPClientDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	clientID := d.Get("client_id").(string)
	body := akeyless_api.KmipDeleteClient{
		ClientId: &clientID,
		Token:    &token,
	}

	if _, res, err := client.KmipDeleteClient(ctx).Body(body).Execute(); err != nil {
		return common.HandleError("failed to delete kmip client", res, err)
	}

	d.SetId("")
	return nil
}

func kmipSetClientState(d *schema.ResourceData, clientItem *akeyless_api.KMIPClient) error {
	if clientItem.Id != nil {
		if err := d.Set("client_id", *clientItem.Id); err != nil {
			return err
		}
		d.SetId(*clientItem.Id)
	}
	if clientItem.Name != nil {
		if err := d.Set("name", *clientItem.Name); err != nil {
			return err
		}
	}
	if clientItem.ActivateKeysOnCreation != nil {
		if err := d.Set("activate_keys_on_creation", *clientItem.ActivateKeysOnCreation); err != nil {
			return err
		}
	}
	if clientItem.CertificateTtlInSeconds != nil {
		if ttl, ok := kmipDaysFromSeconds(*clientItem.CertificateTtlInSeconds); ok {
			if err := d.Set("certificate_ttl", ttl); err != nil {
				return err
			}
		}
	}
	if clientItem.ExpirationEvents != nil {
		if err := d.Set("expiration_event_in", common.ReadExpirationEventInParam(clientItem.ExpirationEvents)); err != nil {
			return err
		}
	}

	return nil
}

func kmipDaysFromSeconds(seconds int64) (int, bool) {
	if seconds <= 0 {
		return 0, false
	}

	if seconds%86400 != 0 {
		return 0, false
	}

	return int(seconds / 86400), true
}
