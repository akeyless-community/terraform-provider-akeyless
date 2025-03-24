package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSSHCertIssuer() *schema.Resource {
	return &schema.Resource{
		Description: "SSH Cert Issuer  resource",
		Create:      resourceSSHCertIssuerCreate,
		Read:        resourceSSHCertIssuerRead,
		Update:      resourceSSHCertIssuerUpdate,
		Delete:      resourceSSHCertIssuerDelete,
		Importer: &schema.ResourceImporter{
			State: resourceSSHCertIssuerImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "SSH certificate issuer name",
				ForceNew:    true,
			},
			"signer_key_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A key to sign the certificate with",
			},
			"allowed_users": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Users allowed to fetch the certificate, e.g root,ubuntu",
			},
			"ttl": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "The requested Time To Live for the certificate, in seconds",
			},
			"principals": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Signed certificates with principal, e.g example_role1,example_role2",
			},
			"external_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Externally provided username [true/false]",
				Default:     "false",
			},
			"extensions": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Signed certificates with extensions (key/val), e.g permit-port-forwarding=",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this key. To specify multiple tags use argument multiple times: --tag Tag1 --tag Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_bastion_api": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Bastion's SSH control API endpoint. E.g. https://my.bastion:9900",
			},
			"secure_access_bastion_ssh": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Bastion's SSH server. E.g. my.bastion:22",
			},
			"secure_access_ssh_creds_user": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "SSH username to connect to target server, must be in 'Allowed Users' list",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Target servers for connections. (In case of Linked Target association, host(s) will inherit Linked Target hosts - Relevant only for Dynamic Secrets/producers)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_use_internal_bastion": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Use internal SSH Bastion",
			},
			"delete_protection": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Protection from accidental deletion of this item, [true/false]",
			},
		},
	}
}

func resourceSSHCertIssuerCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	signerKeyName := d.Get("signer_key_name").(string)
	allowedUsers := d.Get("allowed_users").(string)
	ttl := d.Get("ttl").(int)
	principals := d.Get("principals").(string)
	extensions := d.Get("extensions").(map[string]interface{})
	externalUsername := d.Get("external_username").(string)
	description := d.Get("description").(string)
	tagSet := d.Get("tags").(*schema.Set)
	tag := common.ExpandStringList(tagSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionApi := d.Get("secure_access_bastion_api").(string)
	secureAccessBastionSsh := d.Get("secure_access_bastion_ssh").(string)
	secureAccessSshCredsUser := d.Get("secure_access_ssh_creds_user").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessUseInternalBastion := d.Get("secure_access_use_internal_bastion").(bool)
	deleteProtection := d.Get("delete_protection").(bool)

	body := akeyless_api.CreateSSHCertIssuer{
		Name:          name,
		SignerKeyName: signerKeyName,
		AllowedUsers:  allowedUsers,
		Ttl:           int64(ttl),
		Token:         &token,
	}
	common.GetAkeylessPtr(&body.Principals, principals)
	common.GetAkeylessPtr(&body.Extensions, extensions)
	common.GetAkeylessPtr(&body.ExternalUsername, "false")
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tag, tag)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionApi, secureAccessBastionApi)
	common.GetAkeylessPtr(&body.SecureAccessBastionSsh, secureAccessBastionSsh)
	common.GetAkeylessPtr(&body.SecureAccessSshCredsUser, secureAccessSshCredsUser)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessUseInternalBastion, secureAccessUseInternalBastion)
	common.GetAkeylessPtr(&body.DeleteProtection, strconv.FormatBool(deleteProtection))

	_, _, err := client.CreateSSHCertIssuer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("failed to create ssh cert issuer: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to create ssh cert issuer: %w", err)
	}

	d.SetId(name)

	return nil
}

func resourceSSHCertIssuerRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DescribeItem{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("failed to get value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to get value: %w", err)
	}
	if rOut.DeleteProtection != nil {
		err := d.Set("delete_protection", *rOut.DeleteProtection)
		if err != nil {
			return err
		}
	}
	if rOut.CertificateIssueDetails != nil {
		if rOut.CertificateIssueDetails.MaxTtl != nil {
			err := d.Set("ttl", *rOut.CertificateIssueDetails.MaxTtl)
			if err != nil {
				return err
			}
		}
		if rOut.CertificateIssueDetails.SshCertIssuerDetails != nil {
			ssh := rOut.CertificateIssueDetails.SshCertIssuerDetails
			if ssh.AllowedUsers != nil {
				err := d.Set("allowed_users", strings.Join(ssh.AllowedUsers, ","))
				if err != nil {
					return err
				}
			}
			if ssh.Principals != nil {
				err := d.Set("principals", strings.Join(ssh.Principals, ","))
				if err != nil {
					return err
				}
			}
			if ssh.Extensions != nil {
				err := d.Set("extensions", *ssh.Extensions)
				if err != nil {
					return err
				}
			}
			if ssh.IsExternallyProvidedUser != nil {
				err := d.Set("external_username", strconv.FormatBool(*ssh.IsExternallyProvidedUser))
				if err != nil {
					return err
				}
			}
		}
	}

	if rOut.CertIssuerSignerKeyName != nil {
		err := d.Set("signer_key_name", *rOut.CertIssuerSignerKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.ItemMetadata != nil {
		err := d.Set("description", *rOut.ItemMetadata)
		if err != nil {
			return err
		}
	}
	if rOut.ItemTags != nil {
		err := d.Set("tags", rOut.ItemTags)
		if err != nil {
			return err
		}
	}

	common.GetSraFromItem(d, rOut)
	d.SetId(path)

	return nil
}

func resourceSSHCertIssuerUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	signerKeyName := d.Get("signer_key_name").(string)
	allowedUsers := d.Get("allowed_users").(string)
	ttl := d.Get("ttl").(int)
	principals := d.Get("principals").(string)
	extensions := d.Get("extensions").(map[string]interface{})
	externalUsername := d.Get("external_username").(string)
	description := d.Get("description").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionApi := d.Get("secure_access_bastion_api").(string)
	secureAccessBastionSsh := d.Get("secure_access_bastion_ssh").(string)
	secureAccessSshCredsUser := d.Get("secure_access_ssh_creds_user").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessUseInternalBastion := d.Get("secure_access_use_internal_bastion").(bool)
	deleteProtection := d.Get("delete_protection").(bool)

	tagSet := d.Get("tags").(*schema.Set)
	tagsList := common.ExpandStringList(tagSet.List())

	body := akeyless_api.UpdateSSHCertIssuer{
		Name:          name,
		SignerKeyName: signerKeyName,
		AllowedUsers:  allowedUsers,
		Ttl:           int64(ttl),
		Token:         &token,
	}
	add, remove, err := common.GetTagsForUpdate(d, name, token, tagsList, client)
	if err == nil {
		if len(add) > 0 {
			common.GetAkeylessPtr(&body.AddTag, add)
		}
		if len(remove) > 0 {
			common.GetAkeylessPtr(&body.RmTag, remove)
		}
	}
	common.GetAkeylessPtr(&body.Principals, principals)
	common.GetAkeylessPtr(&body.Extensions, extensions)
	common.GetAkeylessPtr(&body.ExternalUsername, "false")
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionApi, secureAccessBastionApi)
	common.GetAkeylessPtr(&body.SecureAccessBastionSsh, secureAccessBastionSsh)
	common.GetAkeylessPtr(&body.SecureAccessSshCredsUser, secureAccessSshCredsUser)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessUseInternalBastion, secureAccessUseInternalBastion)
	common.GetAkeylessPtr(&body.DeleteProtection, strconv.FormatBool(deleteProtection))

	_, _, err = client.UpdateSSHCertIssuer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("failed to update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to update : %w", err)
	}

	d.SetId(name)

	return nil
}

func resourceSSHCertIssuerDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.DeleteItem{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteItem(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceSSHCertIssuerImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceSSHCertIssuerRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
