package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
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
			"provider_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Provider type",
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
			"extensions": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Signed certificates with extensions, e.g permit-port-forwarding=\"\"",
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
				Description: "List of the tags attached to this key",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access [true/false]",
			},
			"secure_access_bastion_api": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Deprecated. use secure-access-api",
			},
			"secure_access_bastion_ssh": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Deprecated. use secure-access-ssh",
			},
			"secure_access_ssh_creds_user": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "SSH username to connect to target server, must be in 'Allowed Users' list",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Target servers for connections (In case of Linked Target association, host(s) will inherit Linked Target hosts - Relevant only for Dynamic Secrets/producers)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_use_internal_bastion": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Deprecated. Use secure-access-use-internal-ssh-access",
			},
			"delete_protection": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
			},
			"fixed_user_claim_keyname": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "For externally provided users, denotes the key-name of IdP claim to extract the username from (relevant only for external-username=true)",
			},
			"host_provider": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Host provider type [explicit/target], Default Host provider is explicit, Relevant only for Secure Remote Access of ssh cert issuer, ldap rotated secret and ldap dynamic secret",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_api": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Secure Access SSH control API endpoint. E.g. https://my.sra-server:9900",
			},
			"secure_access_enforce_hosts_restriction": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable this flag to enforce connections only to the hosts listed in --secure-access-host",
			},
			"secure_access_gateway": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Secure Access Gateway",
			},
			"secure_access_ssh": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Bastion's SSH server. E.g. my.sra-server:22",
			},
			"secure_access_use_internal_ssh_access": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Use internal SSH Access",
			},
			"target": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of linked targets to be associated, Relevant only for Secure Remote Access for ssh cert issuer, ldap rotated secret and ldap dynamic secret, To specify multiple targets use argument multiple times",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceSSHCertIssuerCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	signerKeyName := d.Get("signer_key_name").(string)
	allowedUsers := d.Get("allowed_users").(string)
	ttl := d.Get("ttl").(int)
	providerType := d.Get("provider_type").(string)
	principals := d.Get("principals").(string)
	extensions := d.Get("extensions").(map[string]interface{})
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
	fixedUserClaimKeyname := d.Get("fixed_user_claim_keyname").(string)
	hostProvider := d.Get("host_provider").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	secureAccessApi := d.Get("secure_access_api").(string)
	secureAccessEnforceHostsRestriction := d.Get("secure_access_enforce_hosts_restriction").(bool)
	secureAccessGateway := d.Get("secure_access_gateway").(string)
	secureAccessSsh := d.Get("secure_access_ssh").(string)
	secureAccessUseInternalSshAccess := d.Get("secure_access_use_internal_ssh_access").(bool)
	targetSet := d.Get("target").(*schema.Set)
	target := common.ExpandStringList(targetSet.List())

	body := akeyless_api.CreateSSHCertIssuer{
		Name:          name,
		SignerKeyName: signerKeyName,
		AllowedUsers:  allowedUsers,
		Ttl:           int64(ttl),
		Token:         &token,
	}
	common.GetAkeylessPtr(&body.ProviderType, providerType)
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
	common.GetAkeylessPtr(&body.FixedUserClaimKeyname, fixedUserClaimKeyname)
	common.GetAkeylessPtr(&body.HostProvider, hostProvider)
	common.GetAkeylessPtr(&body.ItemCustomFields, itemCustomFields)
	common.GetAkeylessPtr(&body.SecureAccessApi, secureAccessApi)
	common.GetAkeylessPtr(&body.SecureAccessEnforceHostsRestriction, secureAccessEnforceHostsRestriction)
	common.GetAkeylessPtr(&body.SecureAccessGateway, secureAccessGateway)
	common.GetAkeylessPtr(&body.SecureAccessSsh, secureAccessSsh)
	common.GetAkeylessPtr(&body.SecureAccessUseInternalSshAccess, secureAccessUseInternalSshAccess)
	common.GetAkeylessPtr(&body.Target, target)

	_, resp, err := client.CreateSSHCertIssuer(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create ssh cert issuer", resp, err)
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
	deleteProtectionVal := false
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = *rOut.DeleteProtection
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
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

	ctx := context.Background()
	name := d.Get("name").(string)
	signerKeyName := d.Get("signer_key_name").(string)
	allowedUsers := d.Get("allowed_users").(string)
	ttl := d.Get("ttl").(int)
	providerType := d.Get("provider_type").(string)
	principals := d.Get("principals").(string)
	extensions := d.Get("extensions").(map[string]interface{})
	description := d.Get("description").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessBastionApi := d.Get("secure_access_bastion_api").(string)
	secureAccessBastionSsh := d.Get("secure_access_bastion_ssh").(string)
	secureAccessSshCredsUser := d.Get("secure_access_ssh_creds_user").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	secureAccessUseInternalBastion := d.Get("secure_access_use_internal_bastion").(bool)
	deleteProtection := d.Get("delete_protection").(bool)
	fixedUserClaimKeyname := d.Get("fixed_user_claim_keyname").(string)
	hostProvider := d.Get("host_provider").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})
	secureAccessApi := d.Get("secure_access_api").(string)
	secureAccessEnforceHostsRestriction := d.Get("secure_access_enforce_hosts_restriction").(bool)
	secureAccessGateway := d.Get("secure_access_gateway").(string)
	secureAccessSsh := d.Get("secure_access_ssh").(string)
	secureAccessUseInternalSshAccess := d.Get("secure_access_use_internal_ssh_access").(bool)

	tagSet := d.Get("tags").(*schema.Set)
	tagsList := common.ExpandStringList(tagSet.List())

	body := akeyless_api.UpdateSSHCertIssuer{
		Name:          name,
		SignerKeyName: signerKeyName,
		AllowedUsers:  allowedUsers,
		Ttl:           int64(ttl),
		Token:         &token,
	}
	common.GetAkeylessPtr(&body.ProviderType, providerType)
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
	common.GetAkeylessPtr(&body.FixedUserClaimKeyname, fixedUserClaimKeyname)
	common.GetAkeylessPtr(&body.HostProvider, hostProvider)
	common.GetAkeylessPtr(&body.ItemCustomFields, itemCustomFields)
	common.GetAkeylessPtr(&body.SecureAccessApi, secureAccessApi)
	common.GetAkeylessPtr(&body.SecureAccessEnforceHostsRestriction, secureAccessEnforceHostsRestriction)
	common.GetAkeylessPtr(&body.SecureAccessGateway, secureAccessGateway)
	common.GetAkeylessPtr(&body.SecureAccessSsh, secureAccessSsh)
	common.GetAkeylessPtr(&body.SecureAccessUseInternalSshAccess, secureAccessUseInternalSshAccess)

	_, resp, err := client.UpdateSSHCertIssuer(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update ", resp, err)
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
