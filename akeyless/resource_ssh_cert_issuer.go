package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v2"
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
				Description: "he requested Time To Live for the certificate, in seconds",
			},
			"principals": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Signed certificates with principal, e.g example_role1,example_role2",
			},
			"extensions": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Signed certificates with extensions, e.g permit-port-forwarding=",
			},
			"metadata": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A metadata about the issuer",
			},
			"tag": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this key. To specify multiple tags use argument multiple times: --tag Tag1 --tag Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_bastion_api": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Bastion's SSH control API endpoint. E.g. https://my.bastion:9900",
			},
			"secure_access_bastion_ssh": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Bastion's SSH server. E.g. my.bastion:22 ",
			},
			"secure_access_ssh_creds_user": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "SSH username to connect to target server, must be in 'Allowed Users' list",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "Target servers for connections., For multiple values repeat this flag.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_use_internal_bastion": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Use internal SSH Bastion",
			},
		},
	}
}

func resourceSSHCertIssuerCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	signerKeyName := d.Get("signer_key_name").(string)
	allowedUsers := d.Get("allowed_users").(string)
	ttl := d.Get("ttl").(int)
	principals := d.Get("principals").(string)
	extensions := d.Get("extensions").(string)
	metadata := d.Get("metadata").(string)
	tagSet := d.Get("tag").(*schema.Set)
	tag := common.ExpandStringList(tagSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionApi := d.Get("secure_access_bastion_api").(string)
	secureAccessBastionSsh := d.Get("secure_access_bastion_ssh").(string)
	secureAccessSshCredsUser := d.Get("secure_access_ssh_creds_user").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessUseInternalBastion := d.Get("secure_access_use_internal_bastion").(bool)

	body := akeyless.CreateSSHCertIssuer{
		Name:          name,
		SignerKeyName: signerKeyName,
		AllowedUsers:  allowedUsers,
		Ttl:           int64(ttl),
		Token:         &token,
	}
	common.GetAkeylessPtr(&body.Principals, principals)
	common.GetAkeylessPtr(&body.Extensions, extensions)
	common.GetAkeylessPtr(&body.Metadata, metadata)
	common.GetAkeylessPtr(&body.Tag, tag)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionApi, secureAccessBastionApi)
	common.GetAkeylessPtr(&body.SecureAccessBastionSsh, secureAccessBastionSsh)
	common.GetAkeylessPtr(&body.SecureAccessSshCredsUser, secureAccessSshCredsUser)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessUseInternalBastion, secureAccessUseInternalBastion)

	_, _, err := client.CreateSSHCertIssuer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceSSHCertIssuerRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.DescribeItem{
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
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}
	if rOut.CertificateIssueDetails != nil {
		if rOut.CertificateIssueDetails.MaxTtl != nil {
			err = d.Set("ttl", *rOut.CertificateIssueDetails.MaxTtl)
			if err != nil {
				return err
			}
		}

		if rOut.CertificateIssueDetails.SshCertIssuerDetails != nil {
			ssh := rOut.CertificateIssueDetails.SshCertIssuerDetails
			if ssh.AllowedUsers != nil {
				err = d.Set("allowed_users", *ssh.AllowedUsers)
				if err != nil {
					return err
				}
			}
			if ssh.Principals != nil {
				err = d.Set("principals", *ssh.Principals)
				if err != nil {
					return err
				}
			}
			if ssh.Extensions != nil {
				err = d.Set("extensions", *ssh.Extensions)
				if err != nil {
					return err
				}
			}
		}
	}

	if rOut.CertIssuerSignerKeyName != nil {
		err = d.Set("signer_key_name", *rOut.CertIssuerSignerKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.ItemMetadata != nil {
		err = d.Set("metadata", *rOut.ItemMetadata)
		if err != nil {
			return err
		}
	}
	if rOut.ItemTags != nil {
		err = d.Set("tag", *rOut.ItemTags)
		if err != nil {
			return err
		}
	}

	common.GetSra(d, path, token, client)

	d.SetId(path)

	return nil
}

func resourceSSHCertIssuerUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	signerKeyName := d.Get("signer_key_name").(string)
	allowedUsers := d.Get("allowed_users").(string)
	ttl := d.Get("ttl").(int)
	principals := d.Get("principals").(string)
	extensions := d.Get("extensions").(string)
	metadata := d.Get("metadata").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionApi := d.Get("secure_access_bastion_api").(string)
	secureAccessBastionSsh := d.Get("secure_access_bastion_ssh").(string)
	secureAccessSshCredsUser := d.Get("secure_access_ssh_creds_user").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessUseInternalBastion := d.Get("secure_access_use_internal_bastion").(bool)

	tagSet := d.Get("tag").(*schema.Set)
	tagsList := common.ExpandStringList(tagSet.List())

	body := akeyless.UpdateSSHCertIssuer{
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
	common.GetAkeylessPtr(&body.Metadata, metadata)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessBastionApi, secureAccessBastionApi)
	common.GetAkeylessPtr(&body.SecureAccessBastionSsh, secureAccessBastionSsh)
	common.GetAkeylessPtr(&body.SecureAccessSshCredsUser, secureAccessSshCredsUser)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.SecureAccessUseInternalBastion, secureAccessUseInternalBastion)

	_, _, err = client.UpdateSSHCertIssuer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceSSHCertIssuerDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteItem{
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
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.DescribeItem{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
