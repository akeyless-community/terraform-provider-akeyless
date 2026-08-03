package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceGatewayMigrationAws() *schema.Resource {
	return &schema.Resource{
		Description: "AWS Migration resource",
		Create:      resourceGatewayMigrationAwsCreate,
		Read:        resourceGatewayMigrationAwsRead,
		Update:      resourceGatewayMigrationAwsUpdate,
		Delete:      resourceGatewayMigrationAwsDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayMigrationAwsImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("aws_key"), cty.GetAttrPath("aws_key_wo")),
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
			"aws_key_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS Access Key ID with sufficient permissions to get all secrets, e.g. 'arn:aws:secretsmanager:[Region]:[AccountId]:secret:[/path/to/secrets/_*]' (relevant only for AWS migration)",
			},
			"aws_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "AWS Secret Access Key (relevant only for AWS migration)",
			},
			"aws_key_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "AWS Secret Access Key (relevant only for AWS migration) (write-only, not stored in state). Requires Terraform 1.11+. Bump aws_key_wo_version to change it.",
			},
			"aws_key_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for aws_key_wo. Increment to update the value.",
			},
			"aws_region": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS region of the required Secrets Manager (relevant only for AWS migration)",
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

func resourceGatewayMigrationAwsCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	awsKeyId := d.Get("aws_key_id").(string)
	awsKey, err := common.EffectiveSecretValue(d, "aws_key", "aws_key_wo")
	if err != nil {
		return err
	}
	awsRegion := d.Get("aws_region").(string)
	protectionKey := d.Get("protection_key").(string)

	body := akeyless_api.NewGatewayCreateMigration("", name, "", "", targetLocation)
	body.Token = &token
	body.Type = akeyless_api.PtrString("aws")
	common.GetAkeylessPtr(&body.AwsKeyId, awsKeyId)
	common.GetAkeylessPtr(&body.AwsKey, awsKey)
	common.GetAkeylessPtr(&body.AwsRegion, awsRegion)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	out, resp, err := client.GatewayCreateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't create Gateway Migration AWS", resp, err)
	}

	migrationID := *out.MigrationId
	d.Set("migration_id", migrationID)

	d.SetId(name)

	return resourceGatewayMigrationAwsRead(d, m)
}

func resourceGatewayMigrationAwsRead(d *schema.ResourceData, m interface{}) error {
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
		return common.HandleReadError(d, "can't get Gateway Migration AWS", res, err)
	}

	if rOut.Body != nil {
		if len(rOut.Body.AwsSecretsMigrations) > 0 {
			for _, migration := range rOut.Body.AwsSecretsMigrations {
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
						if migration.Payload.Region != nil {
							if err := d.Set("aws_region", *migration.Payload.Region); err != nil {
								return err
							}
						}
						if migration.Payload.Key != nil {
							if err := d.Set("aws_key_id", *migration.Payload.Key); err != nil {
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

func resourceGatewayMigrationAwsUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	awsKeyId := d.Get("aws_key_id").(string)
	awsKey, err := common.EffectiveSecretValue(d, "aws_key", "aws_key_wo")
	if err != nil {
		return err
	}
	awsRegion := d.Get("aws_region").(string)
	protectionKey := d.Get("protection_key").(string)

	body := akeyless_api.NewGatewayUpdateMigration("", "", "", targetLocation)
	body.Token = &token
	body.Name = &name
	common.GetAkeylessPtr(&body.AwsKeyId, awsKeyId)
	common.GetAkeylessPtr(&body.AwsKey, awsKey)
	common.GetAkeylessPtr(&body.AwsRegion, awsRegion)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	_, resp, err := client.GatewayUpdateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't update Gateway Migration AWS", resp, err)
	}

	return nil
}

func resourceGatewayMigrationAwsDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceGatewayMigrationAwsImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceGatewayMigrationAwsRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
