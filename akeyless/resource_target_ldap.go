package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceLdapTarget() *schema.Resource {
	return &schema.Resource{
		Description: "LDAP Target resource",
		Create:      resourceLdapTargetCreate,
		Read:        resourceLdapTargetRead,
		Update:      resourceLdapTargetUpdate,
		Delete:      resourceLdapTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceLdapTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"ldap_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "LDAP Server URL",
			},
			"bind_dn": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Bind DN",
			},
			"bind_dn_password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Bind DN Password",
			},
			"ldap_ca_cert": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "CA Certificate File Content",
			},
			"server_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set Ldap server type, Options:[OpenLDAP, ActiveDirectory]. Default is OpenLDAP",
				Default:     "OpenLDAP",
			},
			"token_expiration": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Token expiration",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that used to encrypt the target secret value (if empty, the account default protectionKey key will be used)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults.",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
		},
	}
}

func resourceLdapTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	ldapUrl := d.Get("ldap_url").(string)
	bindDn := d.Get("bind_dn").(string)
	bindDnPassword := d.Get("bind_dn_password").(string)
	ldapCaCert := d.Get("ldap_ca_cert").(string)
	serverType := d.Get("server_type").(string)
	tokenExpiration := d.Get("token_expiration").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)

	body := akeyless_api.CreateLdapTarget{
		Name:           name,
		LdapUrl:        ldapUrl,
		BindDn:         bindDn,
		BindDnPassword: bindDnPassword,
		Token:          &token,
	}
	common.GetAkeylessPtr(&body.LdapCaCert, ldapCaCert)
	common.GetAkeylessPtr(&body.ServerType, serverType)
	common.GetAkeylessPtr(&body.TokenExpiration, tokenExpiration)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.CreateldapTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceLdapTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("failed to get target details: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to get target details: %w", err)
	}

	if rOut.Value != nil {
		targetDetails := *rOut.Value

		if targetDetails.LdapTargetDetails != nil {
			if targetDetails.LdapTargetDetails.LdapUrl != nil {
				err := d.Set("ldap_url", *targetDetails.LdapTargetDetails.LdapUrl)
				if err != nil {
					return err
				}
			}
			if targetDetails.LdapTargetDetails.LdapBindDn != nil {
				err := d.Set("bind_dn", *targetDetails.LdapTargetDetails.LdapBindDn)
				if err != nil {
					return err
				}
			}
			if targetDetails.LdapTargetDetails.LdapBindPassword != nil {
				err := d.Set("bind_dn_password", *targetDetails.LdapTargetDetails.LdapBindPassword)
				if err != nil {
					return err
				}
			}
			if targetDetails.LdapTargetDetails.LdapCertificate != nil {
				err := d.Set("ldap_ca_cert", *targetDetails.LdapTargetDetails.LdapCertificate)
				if err != nil {
					return err
				}
			}
			// Note: ServerType and TokenExpiration may not be returned by the API
		}
	}

	if rOut.Target != nil {
		target := *rOut.Target

		if target.Comment != nil {
			err := d.Set("description", *target.Comment)
			if err != nil {
				return err
			}
		}
		if target.ProtectionKeyName != nil {
			err = d.Set("key", *target.ProtectionKeyName)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceLdapTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	ldapUrl := d.Get("ldap_url").(string)
	bindDn := d.Get("bind_dn").(string)
	bindDnPassword := d.Get("bind_dn_password").(string)
	ldapCaCert := d.Get("ldap_ca_cert").(string)
	serverType := d.Get("server_type").(string)
	tokenExpiration := d.Get("token_expiration").(string)
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.UpdateLdapTarget{
		Name:           name,
		LdapUrl:        ldapUrl,
		BindDn:         bindDn,
		BindDnPassword: bindDnPassword,
		Token:          &token,
	}
	common.GetAkeylessPtr(&body.LdapCaCert, ldapCaCert)
	common.GetAkeylessPtr(&body.ServerType, serverType)
	common.GetAkeylessPtr(&body.TokenExpiration, tokenExpiration)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.UpdateLdapTarget(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceLdapTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.TargetDelete{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.TargetDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceLdapTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceLdapTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
