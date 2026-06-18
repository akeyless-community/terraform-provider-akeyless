package akeyless

import (
	"context"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayMigrationHashi() *schema.Resource {
	return &schema.Resource{
		Description: "HashiCorp Vault Migration resource",
		Create:      resourceGatewayMigrationHashiCreate,
		Read:        resourceGatewayMigrationHashiRead,
		Update:      resourceGatewayMigrationHashiUpdate,
		Delete:      resourceGatewayMigrationHashiDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayMigrationHashiImport,
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
			"hashi_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "HashiCorp Vault API URL, e.g. https://vault-mgr01:8200 (relevant only for HasiCorp Vault migration)",
			},
			"hashi_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "HashiCorp Vault access token with sufficient permissions to preform list & read operations on secrets objects (relevant only for HasiCorp Vault migration)",
			},
			"hashi_ns": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "HashiCorp Vault Namespaces is a comma-separated list of namespaces which need to be imported into Akeyless Vault. For every provided namespace, all its child namespaces are imported as well, e.g. nmsp/subnmsp1/subnmsp2,nmsp/anothernmsp. By default, import all namespaces (relevant only for HasiCorp Vault migration)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"hashi_json": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Import secret key as json value or independent secrets (relevant only for HasiCorp Vault migration) [true/false]",
			},
			"hashi_metadata_mode": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Controls the amount of HashiCorp Vault secret metadata migrated with each secret value. Options: none|minimal|full",
			},
			"protection_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)",
			},
			"migration_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Migration ID",
			},
		},
	}
}

func resourceGatewayMigrationHashiCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	hashiUrl := d.Get("hashi_url").(string)
	hashiToken := d.Get("hashi_token").(string)
	hashiNs := d.Get("hashi_ns").([]interface{})
	hashiJson := d.Get("hashi_json").(string)
	hashiMetadataMode := d.Get("hashi_metadata_mode").(string)
	protectionKey := d.Get("protection_key").(string)

	body := akeyless_api.NewGatewayCreateMigration("", name, "", "", targetLocation)
	body.Token = &token
	body.Type = akeyless_api.PtrString("hashi")
	common.GetAkeylessPtr(&body.HashiUrl, hashiUrl)
	common.GetAkeylessPtr(&body.HashiToken, hashiToken)
	if len(hashiNs) > 0 {
		body.HashiNs = common.ExpandStringList(hashiNs)
	}
	common.GetAkeylessPtr(&body.HashiJson, hashiJson)
	common.GetAkeylessPtr(&body.HashiMetadataMode, hashiMetadataMode)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	out, resp, err := client.GatewayCreateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't create Gateway Migration HashiCorp Vault", resp, err)
	}

	migrationID := *out.MigrationId
	d.Set("migration_id", migrationID)

	d.SetId(name)

	return resourceGatewayMigrationHashiRead(d, m)
}

func resourceGatewayMigrationHashiRead(d *schema.ResourceData, m interface{}) error {
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
		return common.HandleReadError(d, "can't get Gateway Migration HashiCorp", res, err)
	}

	if rOut.Body != nil {
		if len(rOut.Body.HashiMigrations) > 0 {
			for _, migration := range rOut.Body.HashiMigrations {
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
						if migration.Payload.Url != nil {
							if err := d.Set("hashi_url", *migration.Payload.Url); err != nil {
								return err
							}
						}
						if migration.Payload.ImportAsJson != nil {
							if err := d.Set("hashi_json", fmt.Sprintf("%v", *migration.Payload.ImportAsJson)); err != nil {
								return err
							}
						}
						if migration.Payload.MetadataMode != nil {
							if err := d.Set("hashi_metadata_mode", *migration.Payload.MetadataMode); err != nil {
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

func resourceGatewayMigrationHashiUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	hashiUrl := d.Get("hashi_url").(string)
	hashiToken := d.Get("hashi_token").(string)
	hashiNs := d.Get("hashi_ns").([]interface{})
	hashiJson := d.Get("hashi_json").(string)
	hashiMetadataMode := d.Get("hashi_metadata_mode").(string)
	protectionKey := d.Get("protection_key").(string)

	body := akeyless_api.NewGatewayUpdateMigration("", "", "", targetLocation)
	body.Token = &token
	body.Name = &name
	common.GetAkeylessPtr(&body.HashiUrl, hashiUrl)
	common.GetAkeylessPtr(&body.HashiToken, hashiToken)
	if len(hashiNs) > 0 {
		body.HashiNs = common.ExpandStringList(hashiNs)
	}
	common.GetAkeylessPtr(&body.HashiJson, hashiJson)
	common.GetAkeylessPtr(&body.HashiMetadataMode, hashiMetadataMode)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	_, resp, err := client.GatewayUpdateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't update Gateway Migration HashiCorp Vault", resp, err)
	}

	return nil
}

func resourceGatewayMigrationHashiDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceGatewayMigrationHashiImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceGatewayMigrationHashiRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
