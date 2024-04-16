// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretRdp() *schema.Resource {
	return &schema.Resource{
		Description: "RDP Producer resource",
		Create:      resourceDynamicSecretRdpCreate,
		Read:        resourceDynamicSecretRdpRead,
		Update:      resourceDynamicSecretRdpUpdate,
		Delete:      resourceDynamicSecretRdpDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretRdpImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of existing target to use in producer creation",
			},
			"rdp_user_groups": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "RDP UserGroup name(s). Multiple values should be separated by comma",
			},
			"rdp_host_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "RDP Host name",
			},
			"rdp_admin_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "RDP Admin name",
			},
			"rdp_admin_pwd": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "RDP Admin Password",
			},
			"rdp_host_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "RDP Host port",
				Default:     "22",
			},
			"fixed_user_only": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable fixed user only",
				Default:     "false",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"password_length": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The length of the password to be generated",
			},
			"encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Encrypt dynamic secret details with following key",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_rdp_domain": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Required when the Dynamic Secret is used for a domain user",
			},
			"secure_access_rdp_user": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Override the RDP Domain username",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Target servers for connections., For multiple values repeat this flag.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_allow_external_user": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Allow providing external user for a domain users",
				Default:     "false",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable Web Secure Remote Access ",
				Computed:    true,
			},
		},
	}
}

func resourceDynamicSecretRdpCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	rdpUserGroups := d.Get("rdp_user_groups").(string)
	rdpHostName := d.Get("rdp_host_name").(string)
	rdpAdminName := d.Get("rdp_admin_name").(string)
	rdpAdminPwd := d.Get("rdp_admin_pwd").(string)
	rdpHostPort := d.Get("rdp_host_port").(string)
	fixedUserOnly := d.Get("fixed_user_only").(string)
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessRdpDomain := d.Get("secure_access_rdp_domain").(string)
	secureAccessRdpUser := d.Get("secure_access_rdp_user").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessAllowExternalUser := d.Get("secure_access_allow_external_user").(bool)

	body := akeyless.DynamicSecretCreateRdp{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.RdpUserGroups, rdpUserGroups)
	common.GetAkeylessPtr(&body.RdpHostName, rdpHostName)
	common.GetAkeylessPtr(&body.RdpAdminName, rdpAdminName)
	common.GetAkeylessPtr(&body.RdpAdminPwd, rdpAdminPwd)
	common.GetAkeylessPtr(&body.RdpHostPort, rdpHostPort)
	common.GetAkeylessPtr(&body.FixedUserOnly, fixedUserOnly)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessRdpDomain, secureAccessRdpDomain)
	common.GetAkeylessPtr(&body.SecureAccessRdpUser, secureAccessRdpUser)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessAllowExternalUser, secureAccessAllowExternalUser)

	_, _, err := client.DynamicSecretCreateRdp(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretRdpRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()
	body := akeyless.GatewayGetProducer{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GatewayGetProducer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}
	if rOut.FixedUserOnly != nil {
		err = d.Set("fixed_user_only", *rOut.FixedUserOnly)
		if err != nil {
			return err
		}
	}
	if rOut.UserTtl != nil {
		err = d.Set("user_ttl", *rOut.UserTtl)
		if err != nil {
			return err
		}
	}
	if rOut.Tags != nil {
		err = d.Set("tags", *rOut.Tags)
		if err != nil {
			return err
		}
	}

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
		if err != nil {
			return err
		}
	}
	if rOut.Groups != nil {
		err = d.Set("rdp_user_groups", *rOut.Groups)
		if err != nil {
			return err
		}
	}
	if rOut.HostName != nil {
		err = d.Set("rdp_host_name", *rOut.HostName)
		if err != nil {
			return err
		}
	}
	if rOut.AdminName != nil {
		err = d.Set("rdp_admin_name", *rOut.AdminName)
		if err != nil {
			return err
		}
	}
	if rOut.AdminPwd != nil {
		err = d.Set("rdp_admin_pwd", *rOut.AdminPwd)
		if err != nil {
			return err
		}
	}
	if rOut.HostPort != nil {
		err = d.Set("rdp_host_port", *rOut.HostPort)
		if err != nil {
			return err
		}
	}
	if rOut.DynamicSecretKey != nil {
		err = d.Set("encryption_key_name", *rOut.DynamicSecretKey)
		if err != nil {
			return err
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceDynamicSecretRdpUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	rdpUserGroups := d.Get("rdp_user_groups").(string)
	rdpHostName := d.Get("rdp_host_name").(string)
	rdpAdminName := d.Get("rdp_admin_name").(string)
	rdpAdminPwd := d.Get("rdp_admin_pwd").(string)
	rdpHostPort := d.Get("rdp_host_port").(string)
	fixedUserOnly := d.Get("fixed_user_only").(string)
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessRdpDomain := d.Get("secure_access_rdp_domain").(string)
	secureAccessRdpUser := d.Get("secure_access_rdp_user").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessAllowExternalUser := d.Get("secure_access_allow_external_user").(bool)

	body := akeyless.DynamicSecretUpdateRdp{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.RdpUserGroups, rdpUserGroups)
	common.GetAkeylessPtr(&body.RdpHostName, rdpHostName)
	common.GetAkeylessPtr(&body.RdpAdminName, rdpAdminName)
	common.GetAkeylessPtr(&body.RdpAdminPwd, rdpAdminPwd)
	common.GetAkeylessPtr(&body.RdpHostPort, rdpHostPort)
	common.GetAkeylessPtr(&body.FixedUserOnly, fixedUserOnly)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessRdpDomain, secureAccessRdpDomain)
	common.GetAkeylessPtr(&body.SecureAccessRdpUser, secureAccessRdpUser)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessAllowExternalUser, secureAccessAllowExternalUser)

	_, _, err := client.DynamicSecretUpdateRdp(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretRdpDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretRdpImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	return resourceDynamicSecretImport(d, m)
}
