package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayMigrationAzureKv() *schema.Resource {
	return &schema.Resource{
		Description: "Azure Key Vault Migration resource",
		Create:      resourceGatewayMigrationAzureKvCreate,
		Read:        resourceGatewayMigrationAzureKvRead,
		Update:      resourceGatewayMigrationAzureKvUpdate,
		Delete:      resourceGatewayMigrationAzureKvDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayMigrationAzureKvImport,
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
			"azure_kv_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure Key Vault Name (relevant only for Azure Key Vault migration)",
			},
			"azure_client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure Key Vault Access client ID, should be Azure AD App with a service principal (relevant only for Azure Key Vault migration)",
			},
			"azure_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Azure Key Vault secret (relevant only for Azure Key Vault migration)",
			},
			"azure_tenant_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure Key Vault Access tenant ID (relevant only for Azure Key Vault migration)",
			},
			"expiration_event_in": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "How many days before the expiration of the certificate would you like to be notified.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"protection_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of the key that protects the classic key value (if empty, the account default key will be used)",
			},
			"migration_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Migration ID",
			},
		},
	}
}

func resourceGatewayMigrationAzureKvCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	azureKvName := d.Get("azure_kv_name").(string)
	azureClientId := d.Get("azure_client_id").(string)
	azureSecret := d.Get("azure_secret").(string)
	azureTenantId := d.Get("azure_tenant_id").(string)
	protectionKey := d.Get("protection_key").(string)

	body := akeyless_api.NewGatewayCreateMigration("", name, "", "", targetLocation)
	body.Token = &token
	common.GetAkeylessPtr(&body.AzureKvName, azureKvName)
	common.GetAkeylessPtr(&body.AzureClientId, azureClientId)
	common.GetAkeylessPtr(&body.AzureSecret, azureSecret)
	common.GetAkeylessPtr(&body.AzureTenantId, azureTenantId)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	expirationEventInSet := d.Get("expiration_event_in").([]interface{})
	expirationEventIn := common.ExpandStringList(expirationEventInSet)
	if len(expirationEventIn) > 0 {
		body.ExpirationEventIn = expirationEventIn
	}

	_, resp, err := client.GatewayCreateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't create Gateway Migration Azure Key Vault", resp, err)
	}

	d.SetId(name)

	return resourceGatewayMigrationAzureKvRead(d, m)
}

func resourceGatewayMigrationAzureKvRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.GatewayGetMigration{
		Token: &token,
	}

	rOut, res, err := client.GatewayGetMigration(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get Gateway Migration Azure KV", res, err)
	}

	if rOut.Body != nil {
		if rOut.Body.AzureKvMigrations != nil && len(rOut.Body.AzureKvMigrations) > 0 {
			for _, migration := range rOut.Body.AzureKvMigrations {
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
					if migration.Payload != nil {
						if migration.Payload.Name != nil {
							if err := d.Set("azure_kv_name", *migration.Payload.Name); err != nil {
								return err
							}
						}
						if migration.Payload.Client != nil {
							if err := d.Set("azure_client_id", *migration.Payload.Client); err != nil {
								return err
							}
						}
						if migration.Payload.Tenant != nil {
							if err := d.Set("azure_tenant_id", *migration.Payload.Tenant); err != nil {
								return err
							}
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

func resourceGatewayMigrationAzureKvUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	azureKvName := d.Get("azure_kv_name").(string)
	azureClientId := d.Get("azure_client_id").(string)
	azureSecret := d.Get("azure_secret").(string)
	azureTenantId := d.Get("azure_tenant_id").(string)
	protectionKey := d.Get("protection_key").(string)

	body := akeyless_api.NewGatewayUpdateMigration("", "", "", targetLocation)
	body.Token = &token
	body.Name = &name
	common.GetAkeylessPtr(&body.AzureKvName, azureKvName)
	common.GetAkeylessPtr(&body.AzureClientId, azureClientId)
	common.GetAkeylessPtr(&body.AzureSecret, azureSecret)
	common.GetAkeylessPtr(&body.AzureTenantId, azureTenantId)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	expirationEventInSet := d.Get("expiration_event_in").([]interface{})
	expirationEventIn := common.ExpandStringList(expirationEventInSet)
	if len(expirationEventIn) > 0 {
		body.ExpirationEventIn = expirationEventIn
	}

	id := d.Get("migration_id").(string)
	if id == "" {
		err := resourceGatewayMigrationAzureKvRead(d, m)
		if err != nil {
			return err
		}
	}
	id = d.Get("migration_id").(string)
	body.Id = &id

	_, resp, err := client.GatewayUpdateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't update Gateway Migration Azure Key Vault", resp, err)
	}

	return nil
}

func resourceGatewayMigrationAzureKvDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	id := d.Get("migration_id").(string)
	if id == "" {
		err := resourceGatewayMigrationAzureKvRead(d, m)
		if err != nil {
			return err
		}
	}
	id = d.Get("migration_id").(string)

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

func resourceGatewayMigrationAzureKvImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceGatewayMigrationAzureKvRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
