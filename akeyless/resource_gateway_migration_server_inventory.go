package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayMigrationServerInventory() *schema.Resource {
	return &schema.Resource{
		Description: "Server Inventory Migration resource",
		Create:      resourceGatewayMigrationServerInventoryCreate,
		Read:        resourceGatewayMigrationServerInventoryRead,
		Update:      resourceGatewayMigrationServerInventoryUpdate,
		Delete:      resourceGatewayMigrationServerInventoryDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayMigrationServerInventoryImport,
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
			"si_target_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "SSH, Windows or Linked Target Name. (Relevant only for Server Inventory migration)",
			},
			"si_users_path_template": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path location template for migrating users as Rotated Secrets e.g.: .../Users/{COMPUTER_NAME}/{USERNAME} (Relevant only for Server Inventory migration)",
			},
			"si_auto_rotate": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable automatic/recurrent rotation for migrated secrets. Default is false: only manual rotation is allowed for migrated secrets. If set to true, this command should be combined with --si-rotation-interval and --si-rotation-hour parameters (Relevant only for Server Inventory migration)",
			},
			"si_rotation_hour": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The hour of the scheduled rotation in UTC (Relevant only for Server Inventory migration)",
			},
			"si_rotation_interval": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The number of days to wait between every automatic rotation [1-365] (Relevant only for Server Inventory migration)",
			},
			"si_sra_enable_rdp": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable RDP Secure Remote Access for the migrated local users rotated secrets. Default is false: rotated secrets will not be created with SRA (Relevant only for Server Inventory migration)",
			},
			"si_user_groups": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Comma-separated list of groups to migrate users from. If empty, all users from all groups will be migrated (Relevant only for Server Inventory migration)",
			},
			"si_users_ignore": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Comma-separated list of Local Users which should not be migrated (Relevant only for Server Inventory migration)",
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

func resourceGatewayMigrationServerInventoryCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	hosts := d.Get("hosts").(string)
	siTargetName := d.Get("si_target_name").(string)
	siUsersPathTemplate := d.Get("si_users_path_template").(string)
	siAutoRotate := d.Get("si_auto_rotate").(string)
	siRotationHour := d.Get("si_rotation_hour").(int)
	siRotationInterval := d.Get("si_rotation_interval").(int)
	siSraEnableRdp := d.Get("si_sra_enable_rdp").(string)
	siUserGroups := d.Get("si_user_groups").(string)
	siUsersIgnore := d.Get("si_users_ignore").(string)
	protectionKey := d.Get("protection_key").(string)

	body := akeyless_api.NewGatewayCreateMigration(hosts, name, siTargetName, siUsersPathTemplate, targetLocation)
	body.Token = &token
	body.Type = akeyless_api.PtrString("server_inventory")
	common.GetAkeylessPtr(&body.SiAutoRotate, siAutoRotate)
	if siRotationHour != 0 {
		body.SiRotationHour = akeyless_api.PtrInt32(int32(siRotationHour))
	}
	if siRotationInterval != 0 {
		body.SiRotationInterval = akeyless_api.PtrInt32(int32(siRotationInterval))
	}
	common.GetAkeylessPtr(&body.SiSraEnableRdp, siSraEnableRdp)
	common.GetAkeylessPtr(&body.SiUserGroups, siUserGroups)
	common.GetAkeylessPtr(&body.SiUsersIgnore, siUsersIgnore)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	_, resp, err := client.GatewayCreateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't create Gateway Migration Server Inventory", resp, err)
	}

	d.SetId(name)

	return resourceGatewayMigrationServerInventoryRead(d, m)
}

func resourceGatewayMigrationServerInventoryRead(d *schema.ResourceData, m interface{}) error {
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
		return common.HandleReadError(d, "can't get Gateway Migration Server Inventory", res, err)
	}

	if rOut.Body != nil {
		if len(rOut.Body.ServerInventoryMigrations) > 0 {
			for _, migration := range rOut.Body.ServerInventoryMigrations {
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
						p := migration.Payload
						if p.UsersRotatedSecretsPathTemplate != nil {
							if err := d.Set("si_users_path_template", *p.UsersRotatedSecretsPathTemplate); err != nil {
								return err
							}
						}
						if p.AutoRotate != nil {
							if err := d.Set("si_auto_rotate", strconv.FormatBool(*p.AutoRotate)); err != nil {
								return err
							}
						}
						if p.AutoRotateRotationHour != nil {
							if err := d.Set("si_rotation_hour", int(*p.AutoRotateRotationHour)); err != nil {
								return err
							}
						}
						if p.AutoRotateIntervalInDays != nil {
							if err := d.Set("si_rotation_interval", int(*p.AutoRotateIntervalInDays)); err != nil {
								return err
							}
						}
						if p.EnableRdpSra != nil {
							if err := d.Set("si_sra_enable_rdp", strconv.FormatBool(*p.EnableRdpSra)); err != nil {
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

func resourceGatewayMigrationServerInventoryUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	hosts := d.Get("hosts").(string)
	siTargetName := d.Get("si_target_name").(string)
	siUsersPathTemplate := d.Get("si_users_path_template").(string)
	siAutoRotate := d.Get("si_auto_rotate").(string)
	siRotationHour := d.Get("si_rotation_hour").(int)
	siRotationInterval := d.Get("si_rotation_interval").(int)
	siSraEnableRdp := d.Get("si_sra_enable_rdp").(string)
	siUserGroups := d.Get("si_user_groups").(string)
	siUsersIgnore := d.Get("si_users_ignore").(string)
	protectionKey := d.Get("protection_key").(string)

	body := akeyless_api.NewGatewayUpdateMigration(hosts, siTargetName, siUsersPathTemplate, targetLocation)
	body.Token = &token
	body.Name = &name
	common.GetAkeylessPtr(&body.SiAutoRotate, siAutoRotate)
	if siRotationHour != 0 {
		body.SiRotationHour = akeyless_api.PtrInt32(int32(siRotationHour))
	}
	if siRotationInterval != 0 {
		body.SiRotationInterval = akeyless_api.PtrInt32(int32(siRotationInterval))
	}
	common.GetAkeylessPtr(&body.SiSraEnableRdp, siSraEnableRdp)
	common.GetAkeylessPtr(&body.SiUserGroups, siUserGroups)
	common.GetAkeylessPtr(&body.SiUsersIgnore, siUsersIgnore)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	id := d.Get("migration_id").(string)
	if id == "" {
		err := resourceGatewayMigrationServerInventoryRead(d, m)
		if err != nil {
			return err
		}
	}
	id = d.Get("migration_id").(string)
	body.Id = &id

	_, resp, err := client.GatewayUpdateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't update Gateway Migration Server Inventory", resp, err)
	}

	return nil
}

func resourceGatewayMigrationServerInventoryDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	id := d.Get("migration_id").(string)
	if id == "" {
		err := resourceGatewayMigrationServerInventoryRead(d, m)
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

func resourceGatewayMigrationServerInventoryImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceGatewayMigrationServerInventoryRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
