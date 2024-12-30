// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSSHTarget() *schema.Resource {
	return &schema.Resource{
		Description: "SSH Target resource",
		Create:      resourceSSHTargetCreate,
		Read:        resourceSSHTargetRead,
		Update:      resourceSSHTargetUpdate,
		Delete:      resourceSSHTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceSSHTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"host": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "SSH host name",
			},
			"port": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "SSH port",
				Default:     "22",
			},
			"ssh_username": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "SSH username",
			},
			"ssh_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "SSH password to rotate",
			},
			"private_key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "SSH private key",
			},
			"private_key_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "SSH private key password",
			},
			"key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used",
			},
		},
	}
}

func resourceSSHTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	host := d.Get("host").(string)
	port := d.Get("port").(string)
	sshUsername := d.Get("ssh_username").(string)
	sshPassword := d.Get("ssh_password").(string)
	privateKey := d.Get("private_key").(string)
	privateKeyPassword := d.Get("private_key_password").(string)
	key := d.Get("key").(string)

	body := akeyless_api.TargetCreateSsh{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.Port, port)
	common.GetAkeylessPtr(&body.SshUsername, sshUsername)
	common.GetAkeylessPtr(&body.SshPassword, sshPassword)
	common.GetAkeylessPtr(&body.PrivateKey, privateKey)
	common.GetAkeylessPtr(&body.PrivateKeyPassword, privateKeyPassword)
	common.GetAkeylessPtr(&body.Key, key)

	_, _, err := client.TargetCreateSsh(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Target: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Target: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceSSHTargetRead(d *schema.ResourceData, m interface{}) error {
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
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}
	if rOut.Value.SshTargetDetails.Host != nil {
		err = d.Set("host", *rOut.Value.SshTargetDetails.Host)
		if err != nil {
			return err
		}
	}
	if rOut.Value.SshTargetDetails.Port != nil {
		err = d.Set("port", *rOut.Value.SshTargetDetails.Port)
		if err != nil {
			return err
		}
	}
	if rOut.Value.SshTargetDetails.PrivateKey != nil {
		err = d.Set("private_key", *rOut.Value.SshTargetDetails.PrivateKey)
		if err != nil {
			return err
		}
	}
	if rOut.Value.SshTargetDetails.PrivateKeyPassword != nil {
		err = d.Set("private_key_password", *rOut.Value.SshTargetDetails.PrivateKeyPassword)
		if err != nil {
			return err
		}
	}

	if rOut.Value.SshTargetDetails.Username != nil {
		err = d.Set("ssh_username", *rOut.Value.SshTargetDetails.Username)
		if err != nil {
			return err
		}
	}
	if rOut.Value.SshTargetDetails.Password != nil {
		err = d.Set("ssh_password", *rOut.Value.SshTargetDetails.Password)
		if err != nil {
			return err
		}
	}
	if rOut.Target.ProtectionKeyName != nil {
		err = d.Set("key", *rOut.Target.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.Target.Comment != nil {
		err := d.Set("description", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceSSHTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	host := d.Get("host").(string)
	port := d.Get("port").(string)
	sshUsername := d.Get("ssh_username").(string)
	sshPassword := d.Get("ssh_password").(string)
	privateKey := d.Get("private_key").(string)
	privateKeyPassword := d.Get("private_key_password").(string)
	key := d.Get("key").(string)

	body := akeyless_api.TargetUpdateSsh{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.Port, port)
	common.GetAkeylessPtr(&body.SshUsername, sshUsername)
	common.GetAkeylessPtr(&body.SshPassword, sshPassword)
	common.GetAkeylessPtr(&body.PrivateKey, privateKey)
	common.GetAkeylessPtr(&body.PrivateKeyPassword, privateKeyPassword)
	common.GetAkeylessPtr(&body.Key, key)

	_, _, err := client.TargetUpdateSsh(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceSSHTargetDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceSSHTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceSSHTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
