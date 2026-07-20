// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayMigrationConjur() *schema.Resource {
	return &schema.Resource{
		Description: "Conjur Migration resource",
		Create:      resourceGatewayMigrationConjurCreate,
		Read:        resourceGatewayMigrationConjurRead,
		Update:      resourceGatewayMigrationConjurUpdate,
		Delete:      resourceGatewayMigrationConjurDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayMigrationConjurImport,
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
			"conjur_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Conjur server base URL. If conjur_url is HTTPS and Conjur uses a private CA/self-signed certificate, make the CA bundle available on the Gateway and set CONJUR_SSL_CERT_PATH to its path",
			},
			"conjur_account": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Conjur account name set on your Conjur server",
			},
			"conjur_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Conjur username used to authenticate",
			},
			"conjur_api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Conjur API Key for the specified user",
			},
			"protection_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)",
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

func resourceGatewayMigrationConjurCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	conjurUrl := d.Get("conjur_url").(string)
	conjurAccount := d.Get("conjur_account").(string)
	conjurUsername := d.Get("conjur_username").(string)
	conjurApiKey := d.Get("conjur_api_key").(string)
	protectionKey := d.Get("protection_key").(string)
	targetName := d.Get("target_name").(string)

	body := akeyless_api.NewGatewayCreateMigration("", name, "", "", targetLocation)
	body.Token = &token
	body.Type = akeyless_api.PtrString("conjur")
	common.GetAkeylessPtr(&body.ConjurUrl, conjurUrl)
	common.GetAkeylessPtr(&body.ConjurAccount, conjurAccount)
	common.GetAkeylessPtr(&body.ConjurUsername, conjurUsername)
	common.GetAkeylessPtr(&body.ConjurApiKey, conjurApiKey)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)
	common.GetAkeylessPtr(&body.TargetName, targetName)

	out, resp, err := client.GatewayCreateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't create Gateway Migration Conjur", resp, err)
	}

	migrationID := *out.MigrationId
	if err := d.Set("migration_id", migrationID); err != nil {
		return err
	}

	d.SetId(name)

	return resourceGatewayMigrationConjurRead(d, m)
}

func resourceGatewayMigrationConjurRead(d *schema.ResourceData, m interface{}) error {
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
		return common.HandleReadError(d, "can't get Gateway Migration Conjur", res, err)
	}

	if rOut.Body != nil {
		if len(rOut.Body.ConjurMigrations) > 0 {
			for _, migration := range rOut.Body.ConjurMigrations {
				if migration.General != nil && migration.General.Name != nil && *migration.General.Name == path {
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
						if migration.Payload.ConjurUrl != nil {
							if err := d.Set("conjur_url", *migration.Payload.ConjurUrl); err != nil {
								return err
							}
						}
						if migration.Payload.ConjurAccount != nil {
							if err := d.Set("conjur_account", *migration.Payload.ConjurAccount); err != nil {
								return err
							}
						}
						if migration.Payload.ConjurUsername != nil {
							if err := d.Set("conjur_username", *migration.Payload.ConjurUsername); err != nil {
								return err
							}
						}
						if migration.Payload.ConjurApiKey != nil {
							if err := d.Set("conjur_api_key", *migration.Payload.ConjurApiKey); err != nil {
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

func resourceGatewayMigrationConjurUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	conjurUrl := d.Get("conjur_url").(string)
	conjurAccount := d.Get("conjur_account").(string)
	conjurUsername := d.Get("conjur_username").(string)
	conjurApiKey := d.Get("conjur_api_key").(string)
	protectionKey := d.Get("protection_key").(string)
	targetName := d.Get("target_name").(string)

	body := akeyless_api.NewGatewayUpdateMigration("", "", "", targetLocation)
	body.Token = &token
	body.Name = &name
	common.GetAkeylessPtr(&body.ConjurUrl, conjurUrl)
	common.GetAkeylessPtr(&body.ConjurAccount, conjurAccount)
	common.GetAkeylessPtr(&body.ConjurUsername, conjurUsername)
	common.GetAkeylessPtr(&body.ConjurApiKey, conjurApiKey)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)
	common.GetAkeylessPtr(&body.TargetName, targetName)

	_, resp, err := client.GatewayUpdateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't update Gateway Migration Conjur", resp, err)
	}

	return nil
}

func resourceGatewayMigrationConjurDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceGatewayMigrationConjurImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()

	err := resourceGatewayMigrationConjurRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
