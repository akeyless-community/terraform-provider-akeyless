// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAccountSettings() *schema.Resource {
	return &schema.Resource{
		Description:   "Account Settings resource",
		Create:        resourceAccountSettingsUpdate,
		Read:          resourceAccountSettingsRead,
		Update:        resourceAccountSettingsUpdate,
		DeleteContext: resourceAccountSettingsDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAccountSettingsImport,
		},
		Schema: map[string]*schema.Schema{
			"jwt_ttl_default": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Default JWT TTL in minutes",
			},
			"jwt_ttl_min": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Minimum JWT TTL in minutes",
			},
			"jwt_ttl_max": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Maximum JWT TTL in minutes",
			},
			"password_length": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Minimum password length",
			},
			"use_capital_letters": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Require capital letters in passwords [true/false]",
			},
			"use_lower_letters": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Require lower-case letters in passwords [true/false]",
			},
			"use_numbers": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Require numbers in passwords [true/false]",
			},
			"use_special_characters": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Require special characters in passwords [true/false]",
			},
			"default_versioning": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Default versioning setting [true/false]",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Maximum number of versions",
			},
			"dynamic_secret_max_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Maximum dynamic secret TTL in minutes",
			},
			"dynamic_secret_max_ttl_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable maximum dynamic secret TTL [true/false]",
			},
			"items_deletion_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Items deletion protection [true/false]",
			},
			"hide_personal_folder": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Hide personal folder [true/false]",
			},
			"hide_static_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Hide static password [true/false]",
			},
			"invalid_characters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Characters not allowed in item names",
			},
			"item_locking_enabled": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Enable item locking [true/false]",
			},
			"enable_password_expiration": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Enable password expiration [true/false]",
			},
			"password_expiration_days": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Number of days before password expires",
			},
			"password_expiration_notification_days": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Number of days before password expiration to send notification",
			},
			"default_share_link_ttl_minutes": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Default share link TTL in minutes",
			},
			"enable_item_sharing": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Enable item sharing [true/false]",
			},
			"company_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Company name",
			},
		},
	}
}

func resourceAccountSettingsUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	body := akeyless_api.UpdateAccountSettings{
		Token: &token,
	}

	common.GetAkeylessPtr(&body.JwtTtlDefault, d.Get("jwt_ttl_default").(int))
	common.GetAkeylessPtr(&body.JwtTtlMin, d.Get("jwt_ttl_min").(int))
	common.GetAkeylessPtr(&body.JwtTtlMax, d.Get("jwt_ttl_max").(int))
	common.GetAkeylessPtr(&body.PasswordLength, d.Get("password_length").(int))
	common.GetAkeylessPtr(&body.UseCapitalLetters, d.Get("use_capital_letters").(string))
	common.GetAkeylessPtr(&body.UseLowerLetters, d.Get("use_lower_letters").(string))
	common.GetAkeylessPtr(&body.UseNumbers, d.Get("use_numbers").(string))
	common.GetAkeylessPtr(&body.UseSpecialCharacters, d.Get("use_special_characters").(string))
	common.GetAkeylessPtr(&body.DefaultVersioning, d.Get("default_versioning").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DynamicSecretMaxTtl, d.Get("dynamic_secret_max_ttl").(int))
	common.GetAkeylessPtr(&body.DynamicSecretMaxTtlEnable, d.Get("dynamic_secret_max_ttl_enable").(string))
	common.GetAkeylessPtr(&body.ItemsDeletionProtection, d.Get("items_deletion_protection").(string))
	common.GetAkeylessPtr(&body.HidePersonalFolder, d.Get("hide_personal_folder").(string))
	common.GetAkeylessPtr(&body.HideStaticPassword, d.Get("hide_static_password").(string))
	common.GetAkeylessPtr(&body.InvalidCharacters, d.Get("invalid_characters").(string))
	common.GetAkeylessPtr(&body.ItemLockingEnabled, d.Get("item_locking_enabled").(string))
	common.GetAkeylessPtr(&body.EnablePasswordExpiration, d.Get("enable_password_expiration").(string))
	common.GetAkeylessPtr(&body.PasswordExpirationDays, d.Get("password_expiration_days").(string))
	common.GetAkeylessPtr(&body.PasswordExpirationNotificationDays, d.Get("password_expiration_notification_days").(string))
	common.GetAkeylessPtr(&body.DefaultShareLinkTtlMinutes, d.Get("default_share_link_ttl_minutes").(string))
	common.GetAkeylessPtr(&body.EnableItemSharing, d.Get("enable_item_sharing").(string))
	common.GetAkeylessPtr(&body.CompanyName, d.Get("company_name").(string))

	_, resp, err := client.UpdateAccountSettings(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update account settings", resp, err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceAccountSettingsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	body := akeyless_api.GetAccountSettings{
		Token: &token,
	}

	rOut, resp, err := client.GetAccountSettings(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't get account settings", resp, err)
	}

	if rOut.SystemAccessCredsSettings != nil {
		s := rOut.SystemAccessCredsSettings
		if s.JwtTtlDefault != nil {
			if err := d.Set("jwt_ttl_default", int(*s.JwtTtlDefault)); err != nil {
				return err
			}
		}
		if s.JwtTtlMinimum != nil {
			if err := d.Set("jwt_ttl_min", int(*s.JwtTtlMinimum)); err != nil {
				return err
			}
		}
		if s.JwtTtlMaximum != nil {
			if err := d.Set("jwt_ttl_max", int(*s.JwtTtlMaximum)); err != nil {
				return err
			}
		}
	}

	if rOut.GeneralSettings != nil {
		g := rOut.GeneralSettings
		if g.PasswordPolicy != nil {
			pp := g.PasswordPolicy
			if pp.PasswordLength != nil {
				if err := d.Set("password_length", int(*pp.PasswordLength)); err != nil {
					return err
				}
			}
			if pp.UseCapitalLetters != nil {
				if err := d.Set("use_capital_letters", boolToStr(*pp.UseCapitalLetters)); err != nil {
					return err
				}
			}
			if pp.UseLowerLetters != nil {
				if err := d.Set("use_lower_letters", boolToStr(*pp.UseLowerLetters)); err != nil {
					return err
				}
			}
			if pp.UseNumbers != nil {
				if err := d.Set("use_numbers", boolToStr(*pp.UseNumbers)); err != nil {
					return err
				}
			}
			if pp.UseSpecialCharacters != nil {
				if err := d.Set("use_special_characters", boolToStr(*pp.UseSpecialCharacters)); err != nil {
					return err
				}
			}
		}

		if g.HidePersonalFolder != nil {
			if err := d.Set("hide_personal_folder", boolToStr(*g.HidePersonalFolder)); err != nil {
				return err
			}
		}
		if g.HideStaticPassword != nil {
			if err := d.Set("hide_static_password", boolToStr(*g.HideStaticPassword)); err != nil {
				return err
			}
		}
		if g.InvalidCharacters != nil {
			if err := d.Set("invalid_characters", *g.InvalidCharacters); err != nil {
				return err
			}
		}
		if g.ProtectItemsByDefault != nil {
			if err := d.Set("items_deletion_protection", boolToStr(*g.ProtectItemsByDefault)); err != nil {
				return err
			}
		}
		if g.PasswordExpirationInfo != nil {
			pe := g.PasswordExpirationInfo
			if pe.Enable != nil {
				if err := d.Set("enable_password_expiration", boolToStr(*pe.Enable)); err != nil {
					return err
				}
			}
		}

		if g.SharingPolicy != nil {
			sp := g.SharingPolicy
			if sp.Enable != nil {
				if err := d.Set("enable_item_sharing", boolToStr(*sp.Enable)); err != nil {
					return err
				}
			}
		}

		if g.ItemLocking != nil {
			il := g.ItemLocking
			if il.Enable != nil {
				if err := d.Set("item_locking_enabled", boolToStr(*il.Enable)); err != nil {
					return err
				}
			}
		}

		if g.DynamicSecretMaxTtl != nil {
			ds := g.DynamicSecretMaxTtl
			if ds.MaxTtlByMinutes != nil {
				if err := d.Set("dynamic_secret_max_ttl", int(*ds.MaxTtlByMinutes)); err != nil {
					return err
				}
			}
			if ds.Enable != nil {
				if err := d.Set("dynamic_secret_max_ttl_enable", boolToStr(*ds.Enable)); err != nil {
					return err
				}
			}
		}
	}

	if rOut.ObjectVersionSettings != nil {
		ovs := rOut.ObjectVersionSettings
		if ovs.DefaultVersioning != nil {
			if err := d.Set("default_versioning", boolToStr(*ovs.DefaultVersioning)); err != nil {
				return err
			}
		}
	}

	if rOut.CompanyName != nil {
		if err := d.Set("company_name", *rOut.CompanyName); err != nil {
			return err
		}
	}

	return nil
}

func resourceAccountSettingsDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return diag.Diagnostics{common.WarningDiagnostics("Destroying account settings is not supported. The settings will remain as-is.")}
}

func resourceAccountSettingsImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	err := resourceAccountSettingsRead(d, m)
	if err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}

func boolToStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
