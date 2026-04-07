package akeyless

import (
	"context"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayMigrationActiveDirectory() *schema.Resource {
	return &schema.Resource{
		Description: "Active Directory Migration resource",
		Create:      resourceGatewayMigrationActiveDirectoryCreate,
		Read:        resourceGatewayMigrationActiveDirectoryRead,
		Update:      resourceGatewayMigrationActiveDirectoryUpdate,
		Delete:      resourceGatewayMigrationActiveDirectoryDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayMigrationActiveDirectoryImport,
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
			"ad_domain_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Active Directory Domain Name",
			},
			"ad_target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Active Directory LDAP Target Name",
			},
			"ad_user_base_dn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Distinguished Name of User objects to search in Active Directory",
			},
			"ad_computer_base_dn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Distinguished Name of Computer objects to search in Active Directory",
			},
			"ad_discovery_types": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Set migration discovery types (domain-users, computers, local-users)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"ad_domain_users_path_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path location template for migrating domain users as Rotated Secrets",
			},
			"ad_local_users_path_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path location template for migrating local users as Rotated Secrets",
			},
			"ad_targets_path_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path location template for migrating domain servers as SSH/Windows Targets",
			},
			"ad_auto_rotate": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable automatic/recurrent rotation for migrated secrets",
			},
			"ad_rotation_hour": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The hour of the scheduled rotation in UTC",
			},
			"ad_rotation_interval": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The number of days to wait between every automatic rotation [1-365]",
			},
			"ad_sra_enable_rdp": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable RDP Secure Remote Access for the migrated local users rotated secrets",
			},
			"ad_ssh_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the SSH Port for further connection to the domain servers",
			},
			"ad_winrm_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the WinRM Port for further connection to the domain servers",
			},
			"ad_winrm_over_http": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Use WinRM over HTTP",
			},
			"ad_targets_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the target type of the domain servers [ssh/windows]",
			},
			"ad_target_format": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Target format for computers migration (linked/regular)",
			},
			"ad_user_groups": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Comma-separated list of domain groups from which privileged domain users will be migrated",
			},
			"ad_local_users_ignore": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Comma-separated list of Local Users which should not be migrated",
			},
			"ad_os_filter": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Filter by Operating System to run the migration",
			},
			"ad_discover_iis_app": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable discovery of IIS application from each domain server",
			},
			"ad_discover_services": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable discovery of Windows services from each domain server",
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

func resourceGatewayMigrationActiveDirectoryCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	adDomainName := d.Get("ad_domain_name").(string)
	adTargetName := d.Get("ad_target_name").(string)
	adUserBaseDn := d.Get("ad_user_base_dn").(string)
	adComputerBaseDn := d.Get("ad_computer_base_dn").(string)
	adDiscoveryTypes := d.Get("ad_discovery_types").([]interface{})
	adDomainUsersPathTemplate := d.Get("ad_domain_users_path_template").(string)
	adLocalUsersPathTemplate := d.Get("ad_local_users_path_template").(string)
	adTargetsPathTemplate := d.Get("ad_targets_path_template").(string)
	adAutoRotate := d.Get("ad_auto_rotate").(string)
	adRotationHour := d.Get("ad_rotation_hour").(int)
	adRotationInterval := d.Get("ad_rotation_interval").(int)
	adSraEnableRdp := d.Get("ad_sra_enable_rdp").(string)
	adSshPort := d.Get("ad_ssh_port").(string)
	adWinrmPort := d.Get("ad_winrm_port").(string)
	adWinrmOverHttp := d.Get("ad_winrm_over_http").(string)
	adTargetsType := d.Get("ad_targets_type").(string)
	adTargetFormat := d.Get("ad_target_format").(string)
	adUserGroups := d.Get("ad_user_groups").(string)
	adLocalUsersIgnore := d.Get("ad_local_users_ignore").(string)
	adOsFilter := d.Get("ad_os_filter").(string)
	adDiscoverIisApp := d.Get("ad_discover_iis_app").(string)
	adDiscoverServices := d.Get("ad_discover_services").(string)
	protectionKey := d.Get("protection_key").(string)

	body := akeyless_api.NewGatewayCreateMigration("", name, "", "", targetLocation)
	body.Token = &token
	body.Type = akeyless_api.PtrString("active_directory")
	common.GetAkeylessPtr(&body.AdDomainName, adDomainName)
	common.GetAkeylessPtr(&body.AdTargetName, adTargetName)
	common.GetAkeylessPtr(&body.AdUserBaseDn, adUserBaseDn)
	common.GetAkeylessPtr(&body.AdComputerBaseDn, adComputerBaseDn)
	if len(adDiscoveryTypes) > 0 {
		body.AdDiscoveryTypes = common.ExpandStringList(adDiscoveryTypes)
	}
	common.GetAkeylessPtr(&body.AdDomainUsersPathTemplate, adDomainUsersPathTemplate)
	common.GetAkeylessPtr(&body.AdLocalUsersPathTemplate, adLocalUsersPathTemplate)
	common.GetAkeylessPtr(&body.AdTargetsPathTemplate, adTargetsPathTemplate)
	common.GetAkeylessPtr(&body.AdAutoRotate, adAutoRotate)
	if adRotationHour != 0 {
		body.AdRotationHour = akeyless_api.PtrInt32(int32(adRotationHour))
	}
	if adRotationInterval != 0 {
		body.AdRotationInterval = akeyless_api.PtrInt32(int32(adRotationInterval))
	}
	common.GetAkeylessPtr(&body.AdSraEnableRdp, adSraEnableRdp)
	common.GetAkeylessPtr(&body.AdSshPort, adSshPort)
	common.GetAkeylessPtr(&body.AdWinrmPort, adWinrmPort)
	common.GetAkeylessPtr(&body.AdWinrmOverHttp, adWinrmOverHttp)
	common.GetAkeylessPtr(&body.AdTargetsType, adTargetsType)
	common.GetAkeylessPtr(&body.AdTargetFormat, adTargetFormat)
	common.GetAkeylessPtr(&body.AdUserGroups, adUserGroups)
	common.GetAkeylessPtr(&body.AdLocalUsersIgnore, adLocalUsersIgnore)
	common.GetAkeylessPtr(&body.AdOsFilter, adOsFilter)
	common.GetAkeylessPtr(&body.AdDiscoverIisApp, adDiscoverIisApp)
	common.GetAkeylessPtr(&body.AdDiscoverServices, adDiscoverServices)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	_, resp, err := client.GatewayCreateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't create Gateway Migration Active Directory", resp, err)
	}

	d.SetId(name)

	return resourceGatewayMigrationActiveDirectoryRead(d, m)
}

func resourceGatewayMigrationActiveDirectoryRead(d *schema.ResourceData, m interface{}) error {
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
		return common.HandleReadError(d, "can't get Gateway Migration Active Directory", res, err)
	}

	if rOut.Body != nil {
		if len(rOut.Body.ActiveDirectoryMigrations) > 0 {
			for _, migration := range rOut.Body.ActiveDirectoryMigrations {
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
						if p.DomainName != nil {
							if err := d.Set("ad_domain_name", *p.DomainName); err != nil {
								return err
							}
						}
						if p.UserBaseDn != nil {
							if err := d.Set("ad_user_base_dn", *p.UserBaseDn); err != nil {
								return err
							}
						}
						if p.ComputerBaseDn != nil {
							if err := d.Set("ad_computer_base_dn", *p.ComputerBaseDn); err != nil {
								return err
							}
						}
						if len(p.DiscoveryTypes) > 0 {
							if err := d.Set("ad_discovery_types", p.DiscoveryTypes); err != nil {
								return err
							}
						}
						if p.DomainUsersRotatedSecretsPathTemplate != nil {
							if err := d.Set("ad_domain_users_path_template", *p.DomainUsersRotatedSecretsPathTemplate); err != nil {
								return err
							}
						}
						if p.LocalUsersRotatedSecretsPathTemplate != nil {
							if err := d.Set("ad_local_users_path_template", *p.LocalUsersRotatedSecretsPathTemplate); err != nil {
								return err
							}
						}
						if p.DomainServerTargetsPathTemplate != nil {
							if err := d.Set("ad_targets_path_template", *p.DomainServerTargetsPathTemplate); err != nil {
								return err
							}
						}
						if p.AutoRotate != nil {
							if err := d.Set("ad_auto_rotate", strconv.FormatBool(*p.AutoRotate)); err != nil {
								return err
							}
						}
						if p.AutoRotateRotationHour != nil {
							if err := d.Set("ad_rotation_hour", int(*p.AutoRotateRotationHour)); err != nil {
								return err
							}
						}
						if p.AutoRotateIntervalInDays != nil {
							if err := d.Set("ad_rotation_interval", int(*p.AutoRotateIntervalInDays)); err != nil {
								return err
							}
						}
						if p.EnableRdpSra != nil {
							if err := d.Set("ad_sra_enable_rdp", strconv.FormatBool(*p.EnableRdpSra)); err != nil {
								return err
							}
						}
						if p.SshPort != nil {
							if err := d.Set("ad_ssh_port", *p.SshPort); err != nil {
								return err
							}
						}
						if p.WinrmPort != nil {
							if err := d.Set("ad_winrm_port", *p.WinrmPort); err != nil {
								return err
							}
						}
						if p.WinrmOverHttp != nil {
							if err := d.Set("ad_winrm_over_http", strconv.FormatBool(*p.WinrmOverHttp)); err != nil {
								return err
							}
						}
						if p.TargetsType != nil {
							if err := d.Set("ad_targets_type", *p.TargetsType); err != nil {
								return err
							}
						}
						if p.TargetFormat != nil {
							if err := d.Set("ad_target_format", *p.TargetFormat); err != nil {
								return err
							}
						}
						if len(p.UserGroups) > 0 {
							if err := d.Set("ad_user_groups", strings.Join(p.UserGroups, ",")); err != nil {
								return err
							}
						}
						if p.OsFilter != nil {
							if err := d.Set("ad_os_filter", *p.OsFilter); err != nil {
								return err
							}
						}
						if p.DiscoverIisApps != nil {
							if err := d.Set("ad_discover_iis_app", strconv.FormatBool(*p.DiscoverIisApps)); err != nil {
								return err
							}
						}
						if p.DiscoverServices != nil {
							if err := d.Set("ad_discover_services", strconv.FormatBool(*p.DiscoverServices)); err != nil {
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

func resourceGatewayMigrationActiveDirectoryUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	adDomainName := d.Get("ad_domain_name").(string)
	adTargetName := d.Get("ad_target_name").(string)
	adUserBaseDn := d.Get("ad_user_base_dn").(string)
	adComputerBaseDn := d.Get("ad_computer_base_dn").(string)
	adDiscoveryTypes := d.Get("ad_discovery_types").([]interface{})
	adDomainUsersPathTemplate := d.Get("ad_domain_users_path_template").(string)
	adLocalUsersPathTemplate := d.Get("ad_local_users_path_template").(string)
	adTargetsPathTemplate := d.Get("ad_targets_path_template").(string)
	adAutoRotate := d.Get("ad_auto_rotate").(string)
	adRotationHour := d.Get("ad_rotation_hour").(int)
	adRotationInterval := d.Get("ad_rotation_interval").(int)
	adSraEnableRdp := d.Get("ad_sra_enable_rdp").(string)
	adSshPort := d.Get("ad_ssh_port").(string)
	adWinrmPort := d.Get("ad_winrm_port").(string)
	adWinrmOverHttp := d.Get("ad_winrm_over_http").(string)
	adTargetsType := d.Get("ad_targets_type").(string)
	adTargetFormat := d.Get("ad_target_format").(string)
	adUserGroups := d.Get("ad_user_groups").(string)
	adLocalUsersIgnore := d.Get("ad_local_users_ignore").(string)
	adOsFilter := d.Get("ad_os_filter").(string)
	adDiscoverIisApp := d.Get("ad_discover_iis_app").(string)
	adDiscoverServices := d.Get("ad_discover_services").(string)
	protectionKey := d.Get("protection_key").(string)

	body := akeyless_api.NewGatewayUpdateMigration("", "", "", targetLocation)
	body.Token = &token
	body.Name = &name
	common.GetAkeylessPtr(&body.AdDomainName, adDomainName)
	common.GetAkeylessPtr(&body.AdTargetName, adTargetName)
	common.GetAkeylessPtr(&body.AdUserBaseDn, adUserBaseDn)
	common.GetAkeylessPtr(&body.AdComputerBaseDn, adComputerBaseDn)
	if len(adDiscoveryTypes) > 0 {
		body.AdDiscoveryTypes = common.ExpandStringList(adDiscoveryTypes)
	}
	common.GetAkeylessPtr(&body.AdDomainUsersPathTemplate, adDomainUsersPathTemplate)
	common.GetAkeylessPtr(&body.AdLocalUsersPathTemplate, adLocalUsersPathTemplate)
	common.GetAkeylessPtr(&body.AdTargetsPathTemplate, adTargetsPathTemplate)
	common.GetAkeylessPtr(&body.AdAutoRotate, adAutoRotate)
	if adRotationHour != 0 {
		body.AdRotationHour = akeyless_api.PtrInt32(int32(adRotationHour))
	}
	if adRotationInterval != 0 {
		body.AdRotationInterval = akeyless_api.PtrInt32(int32(adRotationInterval))
	}
	common.GetAkeylessPtr(&body.AdSraEnableRdp, adSraEnableRdp)
	common.GetAkeylessPtr(&body.AdSshPort, adSshPort)
	common.GetAkeylessPtr(&body.AdWinrmPort, adWinrmPort)
	common.GetAkeylessPtr(&body.AdWinrmOverHttp, adWinrmOverHttp)
	common.GetAkeylessPtr(&body.AdTargetsType, adTargetsType)
	common.GetAkeylessPtr(&body.AdTargetFormat, adTargetFormat)
	common.GetAkeylessPtr(&body.AdUserGroups, adUserGroups)
	common.GetAkeylessPtr(&body.AdLocalUsersIgnore, adLocalUsersIgnore)
	common.GetAkeylessPtr(&body.AdOsFilter, adOsFilter)
	common.GetAkeylessPtr(&body.AdDiscoverIisApp, adDiscoverIisApp)
	common.GetAkeylessPtr(&body.AdDiscoverServices, adDiscoverServices)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	id := d.Get("migration_id").(string)
	if id == "" {
		err := resourceGatewayMigrationActiveDirectoryRead(d, m)
		if err != nil {
			return err
		}
	}
	id = d.Get("migration_id").(string)
	body.Id = &id

	_, resp, err := client.GatewayUpdateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't update Gateway Migration Active Directory", resp, err)
	}

	return nil
}

func resourceGatewayMigrationActiveDirectoryDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	id := d.Get("migration_id").(string)
	if id == "" {
		err := resourceGatewayMigrationActiveDirectoryRead(d, m)
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

func resourceGatewayMigrationActiveDirectoryImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceGatewayMigrationActiveDirectoryRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
