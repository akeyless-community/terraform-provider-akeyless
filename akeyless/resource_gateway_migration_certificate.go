package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayMigrationCertificate() *schema.Resource {
	return &schema.Resource{
		Description: "Certificate Migration resource",
		Create:      resourceGatewayMigrationCertificateCreate,
		Read:        resourceGatewayMigrationCertificateRead,
		Update:      resourceGatewayMigrationCertificateUpdate,
		Delete:      resourceGatewayMigrationCertificateDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayMigrationCertificateImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Migration name",
				ForceNew:    true,
			},
			"target_location": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target location in Akeyless for imported secrets",
			},
			"hosts": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A comma separated list of IPs, CIDR ranges, or DNS names to scan",
			},
			"port_ranges": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma separated list of port ranges Examples: \"80,443\" or \"80,443,8080-8090\" or \"443\"",
			},
			"expiration_event_in": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "How many days before the expiration of the certificate would you like to be notified",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"protection_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of the key that protects the classic key value (if empty, the account default key will be used)",
			},
			"target_name": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Name of existing target to use to create the migration",
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"migration_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Migration ID",
			},
		},
	}
}

func resourceGatewayMigrationCertificateCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	hosts := d.Get("hosts").(string)
	portRanges := d.Get("port_ranges").(string)
	expirationEventIn := d.Get("expiration_event_in").([]interface{})
	protectionKey := d.Get("protection_key").(string)
	targetName := d.Get("target_name").(string)

	body := akeyless_api.NewGatewayCreateMigration(hosts, name, "", "", targetLocation)
	body.Token = &token
	body.Type = akeyless_api.PtrString("certificate")
	common.GetAkeylessPtr(&body.PortRanges, portRanges)
	if len(expirationEventIn) > 0 {
		body.ExpirationEventIn = common.ExpandStringList(expirationEventIn)
	}
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)
	common.GetAkeylessPtr(&body.TargetName, targetName)

	out, resp, err := client.GatewayCreateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't create Gateway Migration Certificate", resp, err)
	}

	migrationID := *out.MigrationId
	d.Set("migration_id", migrationID)

	d.SetId(name)

	return resourceGatewayMigrationCertificateRead(d, m)
}

func resourceGatewayMigrationCertificateRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.GatewayGetMigration{
		Name:  &path,
		Token: &token,
	}

	rOut, res, err := client.GatewayGetMigration(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get Gateway Migration Certificate", res, err)
	}

	if rOut.Body != nil {
		if len(rOut.Body.CertificateMigrations) > 0 {
			for _, migration := range rOut.Body.CertificateMigrations {
				if migration.General != nil && *migration.General.Name == path {
					if migration.General.Id != nil {
						if err := d.Set("migration_id", *migration.General.Id); err != nil {
							return err
						}
					}
					if migration.General.ProtectionKey != nil {
						if err := d.Set("protection_key", *migration.General.ProtectionKey); err != nil {
							return err
						}
					}
					if migration.General.Prefix != nil {
						if err := d.Set("target_location", *migration.General.Prefix); err != nil {
							return err
						}
					}
					if migration.Payload != nil && migration.Payload.PortRanges != nil {
						if err := d.Set("port_ranges", *migration.Payload.PortRanges); err != nil {
							return err
						}
					}
					break
				}
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceGatewayMigrationCertificateUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	hosts := d.Get("hosts").(string)
	portRanges := d.Get("port_ranges").(string)
	expirationEventIn := d.Get("expiration_event_in").([]interface{})
	protectionKey := d.Get("protection_key").(string)
	targetName := d.Get("target_name").(string)

	body := akeyless_api.NewGatewayUpdateMigration(hosts, "", "", targetLocation)
	body.Token = &token
	body.Name = &name
	common.GetAkeylessPtr(&body.PortRanges, portRanges)
	if len(expirationEventIn) > 0 {
		body.ExpirationEventIn = common.ExpandStringList(expirationEventIn)
	}
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)
	common.GetAkeylessPtr(&body.TargetName, targetName)

	_, resp, err := client.GatewayUpdateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't update Gateway Migration Certificate", resp, err)
	}

	return nil
}

func resourceGatewayMigrationCertificateDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	id := d.Get("migration_id").(string)

	deleteItem := akeyless_api.GatewayDeleteMigration{
		Token: &token,
		Id:    id,
	}

	ctx := context.Background()
	_, _, err := client.GatewayDeleteMigration(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceGatewayMigrationCertificateImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceGatewayMigrationCertificateRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
