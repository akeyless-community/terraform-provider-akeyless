// generated fule
package akeyless

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceProducerLdap() *schema.Resource {
	return &schema.Resource{
		Description: "LDAP producer resource",
		Create:      resourceProducerLdapCreate,
		Read:        resourceProducerLdapRead,
		Update:      resourceProducerLdapUpdate,
		Delete:      resourceProducerLdapDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerLdapImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Producer name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Name of existing target to use in producer creation",
			},
			"ldap_url": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "LDAP Server URL",
			},
			"user_dn": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "User Base DN",
			},
			"user_attribute": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "LDAP User Attribute",
			},
			"ldap_ca_cert": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "LDAP base-64 encoded CA Certificate",
			},
			"bind_dn": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "LDAP Bind DN",
			},
			"bind_dn_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Password for LDAP Bind DN",
			},
			"external_username": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Externally provided username",
				Default:     "false",
			},
			"token_expiration": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "LDAP token expiration in seconds",
				Default:     "60",
			},
			"producer_encryption_key_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Encrypt producer with following key",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"tags": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: --tag Tag1 --tag Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceProducerLdapCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	ldapUrl := d.Get("ldap_url").(string)
	userDn := d.Get("user_dn").(string)
	userAttribute := d.Get("user_attribute").(string)
	ldapCaCert := d.Get("ldap_ca_cert").(string)
	bindDn := d.Get("bind_dn").(string)
	bindDnPassword := d.Get("bind_dn_password").(string)
	externalUsername := d.Get("external_username").(string)
	tokenExpiration := d.Get("token_expiration").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless.GatewayCreateProducerLdap{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.LdapUrl, ldapUrl)
	common.GetAkeylessPtr(&body.UserDn, userDn)
	common.GetAkeylessPtr(&body.UserAttribute, userAttribute)
	common.GetAkeylessPtr(&body.LdapCaCert, ldapCaCert)
	common.GetAkeylessPtr(&body.BindDn, bindDn)
	common.GetAkeylessPtr(&body.BindDnPassword, bindDnPassword)
	common.GetAkeylessPtr(&body.ExternalUsername, externalUsername)
	common.GetAkeylessPtr(&body.TokenExpiration, tokenExpiration)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)

	_, _, err := client.GatewayCreateProducerLdap(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerLdapRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.LdapUrl != nil {
		err = d.Set("ldap_url", *rOut.LdapUrl)
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

	if rOut.LdapUserDn != nil {
		err = d.Set("user_dn", *rOut.LdapUserDn)
		if err != nil {
			return err
		}
	}
	if rOut.LdapUserAttr != nil {
		err = d.Set("user_attribute", *rOut.LdapUserAttr)
		if err != nil {
			return err
		}
	}
	if rOut.LdapCertificate != nil {
		certEncodedData := base64.StdEncoding.EncodeToString([]byte(*rOut.LdapCertificate))
		err = d.Set("ldap_ca_cert", certEncodedData)
		if err != nil {
			return err
		}
	}
	if rOut.LdapBindDn != nil {
		err = d.Set("bind_dn", *rOut.LdapBindDn)
		if err != nil {
			return err
		}
	}
	if rOut.LdapBindPassword != nil {
		err = d.Set("bind_dn_password", *rOut.LdapBindPassword)
		if err != nil {
			return err
		}
	}
	if rOut.FixedUserOnly != nil {
		err = d.Set("external_username", *rOut.FixedUserOnly)
		if err != nil {
			return err
		}
	}
	if rOut.LdapTokenExpiration != nil {
		err = d.Set("token_expiration", *rOut.LdapTokenExpiration)
		if err != nil {
			return err
		}
	}
	if rOut.DynamicSecretKey != nil {
		err = d.Set("producer_encryption_key_name", *rOut.DynamicSecretKey)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceProducerLdapUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	ldapUrl := d.Get("ldap_url").(string)
	userDn := d.Get("user_dn").(string)
	userAttribute := d.Get("user_attribute").(string)
	ldapCaCert := d.Get("ldap_ca_cert").(string)
	bindDn := d.Get("bind_dn").(string)
	bindDnPassword := d.Get("bind_dn_password").(string)
	externalUsername := d.Get("external_username").(string)
	tokenExpiration := d.Get("token_expiration").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless.GatewayUpdateProducerLdap{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.LdapUrl, ldapUrl)
	common.GetAkeylessPtr(&body.UserDn, userDn)
	common.GetAkeylessPtr(&body.UserAttribute, userAttribute)
	common.GetAkeylessPtr(&body.LdapCaCert, ldapCaCert)
	common.GetAkeylessPtr(&body.BindDn, bindDn)
	common.GetAkeylessPtr(&body.BindDnPassword, bindDnPassword)
	common.GetAkeylessPtr(&body.ExternalUsername, externalUsername)
	common.GetAkeylessPtr(&body.TokenExpiration, tokenExpiration)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)

	_, _, err := client.GatewayUpdateProducerLdap(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerLdapDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.GatewayDeleteProducer{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.GatewayDeleteProducer(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceProducerLdapImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GatewayGetProducer{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GatewayGetProducer(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
