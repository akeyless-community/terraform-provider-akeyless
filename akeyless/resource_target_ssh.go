// generated file
package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
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
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("private_key_password"), cty.GetAttrPath("private_key_password_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("private_key"), cty.GetAttrPath("private_key_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("ssh_password"), cty.GetAttrPath("ssh_password_wo")),
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
			"ssh_password_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"ssh_password_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "ssh_password (write-only, not stored in state). Requires Terraform 1.11+. Bump ssh_password_wo_version to change it.",
			},
			"ssh_password_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"ssh_password_wo"},
				Description:  "Version trigger for ssh_password_wo. Increment to update the value.",
			},
			"private_key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "SSH private key",
			},
			"private_key_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"private_key_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "private_key (write-only, not stored in state). Requires Terraform 1.11+. Bump private_key_wo_version to change it.",
			},
			"private_key_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"private_key_wo"},
				Description:  "Version trigger for private_key_wo. Increment to update the value.",
			},
			"private_key_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "SSH private key password",
			},
			"private_key_password_wo": {
				Type:         schema.TypeString,
				Optional:     true,
				RequiredWith: []string{"private_key_password_wo_version"},
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "private_key_password (write-only, not stored in state). Requires Terraform 1.11+. Bump private_key_password_wo_version to change it.",
			},
			"private_key_password_wo_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				RequiredWith: []string{"private_key_password_wo"},
				Description:  "Version trigger for private_key_password_wo. Increment to update the value.",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key that used to encrypt the target secret value (if empty, the account default protectionKey key will be used)",
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

func resourceSSHTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	host := d.Get("host").(string)
	port := d.Get("port").(string)
	sshUsername := d.Get("ssh_username").(string)
	sshPassword, err := common.EffectiveSecretValue(d, "ssh_password", "ssh_password_wo")
	if err != nil {
		return err
	}
	privateKey, err := common.EffectiveSecretValue(d, "private_key", "private_key_wo")
	if err != nil {
		return err
	}
	privateKeyPassword, err := common.EffectiveSecretValue(d, "private_key_password", "private_key_password_wo")
	if err != nil {
		return err
	}
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)

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
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)

	_, resp, err := client.TargetCreateSsh(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceSSHTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get target details", res, err)
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
		err = common.SetSecretFromRead(d, "private_key", "private_key_wo", "private_key_wo_version", *rOut.Value.SshTargetDetails.PrivateKey)
		if err != nil {
			return err
		}
	}
	if rOut.Value.SshTargetDetails.PrivateKeyPassword != nil {
		err = common.SetSecretFromRead(d, "private_key_password", "private_key_password_wo", "private_key_password_wo_version", *rOut.Value.SshTargetDetails.PrivateKeyPassword)
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
		err = common.SetSecretFromRead(d, "ssh_password", "ssh_password_wo", "ssh_password_wo_version", *rOut.Value.SshTargetDetails.Password)
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

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	host := d.Get("host").(string)
	port := d.Get("port").(string)
	sshUsername := d.Get("ssh_username").(string)
	sshPassword, err := common.SecretValueForUpdate(d, "ssh_password", "ssh_password_wo")
	if err != nil {
		return err
	}
	privateKey, err := common.SecretValueForUpdate(d, "private_key", "private_key_wo")
	if err != nil {
		return err
	}
	privateKeyPassword, err := common.SecretValueForUpdate(d, "private_key_password", "private_key_password_wo")
	if err != nil {
		return err
	}
	key := d.Get("key").(string)
	maxVersions := d.Get("max_versions").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)

	body := akeyless_api.TargetUpdateSsh{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Host, host)
	common.GetAkeylessPtr(&body.Port, port)
	common.GetAkeylessPtr(&body.SshUsername, sshUsername)
	common.SetOptionalString(&body.SshPassword, sshPassword)
	common.SetOptionalString(&body.PrivateKey, privateKey)
	common.SetOptionalString(&body.PrivateKeyPassword, privateKeyPassword)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.MaxVersions, maxVersions)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)

	_, resp, err := client.TargetUpdateSsh(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
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
