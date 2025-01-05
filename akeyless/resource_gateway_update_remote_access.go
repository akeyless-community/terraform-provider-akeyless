// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayUpdateRemoteAccess() *schema.Resource {
	return &schema.Resource{
		Description: "Remote access config",
		Create:      resourceGatewayUpdateRemoteAccessUpdate,
		Read:        resourceGatewayUpdateRemoteAccessRead,
		Update:      resourceGatewayUpdateRemoteAccessUpdate,
		Delete:      resourceGatewayUpdateRemoteAccessUpdate,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateRemoteAccessImport,
		},
		Schema: map[string]*schema.Schema{
			"allowed_urls": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "List of valid URLs to redirect from the Portal back to the remote access server (in a comma-delimited list)",
				Default:     "use-existing",
			},
			"legacy_ssh_algorithm": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Signs SSH certificates using legacy ssh-rsa-cert-01@openssh.com signing algorithm [true/false]",
			},
			"rdp_target_configuration": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specify the usernameSubClaim that exists inside the IDP JWT, e.g. email",
				Default:     "use-existing",
			},
			"ssh_target_configuration": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specify the usernameSubClaim that exists inside the IDP JWT, e.g. email",
				Default:     "use-existing",
			},
			"kexalgs": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Decide which algorithm will be used as part of the SSH initial hand-shake process",
				Default:     "use-existing",
			},
			"hide_session_recording": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies whether to show/hide if the session is currently recorded [true/false]",
			},
			"keyboard_layout": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable support for additional keyboard layouts",
				Default:     "use-existing",
			},
		},
	}
}

func resourceGatewayUpdateRemoteAccessRead(d *schema.ResourceData, m interface{}) error {
	rOut, err := getGwRemoteAccessConfig(m)
	if err != nil {
		return err
	}

	globalConfig := rOut.Global
	if globalConfig != nil {
		if globalConfig.AllowedBastionUrls != nil && d.Get("allowed_urls").(string) != common.UseExisting {
			err = d.Set("allowed_urls", strings.Join(*globalConfig.AllowedBastionUrls, ","))
			if err != nil {
				return err
			}
		}
		if globalConfig.LegacySigningAlg != nil && d.Get("legacy_ssh_algorithm") != "" {
			err = d.Set("legacy_ssh_algorithm", strconv.FormatBool(*globalConfig.LegacySigningAlg))
			if err != nil {
				return err
			}
		}
		if globalConfig.RdpUsernameSubClaim != nil && d.Get("rdp_target_configuration").(string) != common.UseExisting {
			err = d.Set("rdp_target_configuration", *globalConfig.RdpUsernameSubClaim)
			if err != nil {
				return err
			}
		}
		if globalConfig.SshUsernameSubClaim != nil && d.Get("ssh_target_configuration").(string) != common.UseExisting {
			err = d.Set("ssh_target_configuration", *globalConfig.SshUsernameSubClaim)
			if err != nil {
				return err
			}
		}
	}

	if rOut.SshBastion != nil {
		if rOut.SshBastion.Kexalgs != nil && d.Get("kexalgs").(string) != common.UseExisting {
			err = d.Set("kexalgs", *rOut.SshBastion.Kexalgs)
			if err != nil {
				return err
			}
		}
		if rOut.SshBastion.HideSessionRecording != nil && d.Get("hide_session_recording") != "" {
			err = d.Set("hide_session_recording", strconv.FormatBool(*rOut.SshBastion.HideSessionRecording))
			if err != nil {
				return err
			}
		}

	}

	if rOut.WebBastion != nil {
		webBastion := rOut.WebBastion
		if webBastion.Guacamole != nil {
			guacamole := webBastion.Guacamole
			if guacamole.KeyboardLayout != nil && d.Get("keyboard_layout").(string) != common.UseExisting {
				err = d.Set("keyboard_layout", *rOut.WebBastion.Guacamole.KeyboardLayout)
				if err != nil {
					return err
				}
			}
		}
	}

	d.SetId(*rOut.ClusterId)

	return nil
}

func resourceGatewayUpdateRemoteAccessUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	allowedUrls := d.Get("allowed_urls").(string)
	legacySshAlgorithm := d.Get("legacy_ssh_algorithm").(string)
	rdpTargetConfiguration := d.Get("rdp_target_configuration").(string)
	sshTargetConfiguration := d.Get("ssh_target_configuration").(string)
	kexalgs := d.Get("kexalgs").(string)
	hideSessionRecording := d.Get("hide_session_recording").(string)
	keyboardLayout := d.Get("keyboard_layout").(string)

	body := akeyless_api.GatewayUpdateRemoteAccess{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AllowedUrls, allowedUrls)
	common.GetAkeylessPtr(&body.LegacySshAlgorithm, legacySshAlgorithm)
	common.GetAkeylessPtr(&body.RdpTargetConfiguration, rdpTargetConfiguration)
	common.GetAkeylessPtr(&body.SshTargetConfiguration, sshTargetConfiguration)
	common.GetAkeylessPtr(&body.Kexalgs, kexalgs)
	common.GetAkeylessPtr(&body.HideSessionRecording, hideSessionRecording)
	common.GetAkeylessPtr(&body.KeyboardLayout, keyboardLayout)

	_, _, err := client.GatewayUpdateRemoteAccess(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update remote access config: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update remote access config: %v", err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGatewayUpdateRemoteAccessImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	// import here is not using read function as bool params strings have no default value therefore
	// they will be set to empty string and won't be read in read function
	rOut, err := getGwRemoteAccessConfig(m)
	if err != nil {
		return nil, err
	}

	globalConfig := rOut.Global
	if globalConfig != nil {
		if globalConfig.AllowedBastionUrls != nil {
			err = d.Set("allowed_urls", strings.Join(*globalConfig.AllowedBastionUrls, ","))
			if err != nil {
				return nil, err
			}
		}
		if globalConfig.LegacySigningAlg != nil {
			err = d.Set("legacy_ssh_algorithm", strconv.FormatBool(*globalConfig.LegacySigningAlg))
			if err != nil {
				return nil, err
			}
		}
		if globalConfig.RdpUsernameSubClaim != nil {
			err = d.Set("rdp_target_configuration", *globalConfig.RdpUsernameSubClaim)
			if err != nil {
				return nil, err
			}
		}
		if globalConfig.SshUsernameSubClaim != nil {
			err = d.Set("ssh_target_configuration", *globalConfig.SshUsernameSubClaim)
			if err != nil {
				return nil, err
			}
		}
	}

	if rOut.SshBastion != nil {
		if rOut.SshBastion.Kexalgs != nil {
			err = d.Set("kexalgs", *rOut.SshBastion.Kexalgs)
			if err != nil {
				return nil, err
			}
		}
		if rOut.SshBastion.HideSessionRecording != nil {
			err = d.Set("hide_session_recording", strconv.FormatBool(*rOut.SshBastion.HideSessionRecording))
			if err != nil {
				return nil, err
			}
		}

	}

	if rOut.WebBastion != nil {
		webBastion := rOut.WebBastion
		if webBastion.Guacamole != nil {
			guacamole := webBastion.Guacamole
			if guacamole.KeyboardLayout != nil {
				err = d.Set("keyboard_layout", *rOut.WebBastion.Guacamole.KeyboardLayout)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	d.SetId(*rOut.ClusterId)

	return []*schema.ResourceData{d}, nil
}

func getGwRemoteAccessConfig(m interface{}) (akeyless_api.BastionConfigReplyObj, error) {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	body := akeyless_api.GatewayGetRemoteAccess{
		Token: &token,
	}

	rOut, _, err := client.GatewayGetRemoteAccess(ctx).Body(body).Execute()
	if err != nil {
		var apiErr akeyless_api.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			return akeyless_api.BastionConfigReplyObj{}, fmt.Errorf("can't get remote access config: %v", string(apiErr.Body()))
		}
		return akeyless_api.BastionConfigReplyObj{}, fmt.Errorf("can't get remote access config: %v", err)
	}
	return rOut, nil
}
