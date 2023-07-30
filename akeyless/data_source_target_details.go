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

func dataSourceGetTargetDetails() *schema.Resource {
	return &schema.Resource{
		Description: "Get target details data source",
		Read:        dataSourceGetTargetDetailsRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"target_version": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Target version",
			},
			"show_versions": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Include all target versions in reply",
				Default:     "false",
			},
			"username": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"password": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
				Sensitive:   true,
			},
			"host": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"port": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"private_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"private_key_password": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
		},
	}
}

func dataSourceGetTargetDetailsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetVersion := d.Get("target_version").(int)
	showVersions := d.Get("show_versions").(bool)

	body := akeyless.GetTargetDetails{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetVersion, targetVersion)
	common.GetAkeylessPtr(&body.ShowVersions, showVersions)

	rOut, res, err := client.GetTargetDetails(ctx).Body(body).Execute()
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
	if rOut.Value == nil {
		return fmt.Errorf("can't get value")
	}
	if rOut.Value.SshTargetDetails.Username != nil {
		err = d.Set("username", *rOut.Value.SshTargetDetails.Username)
		if err != nil {
			return err
		}
	}
	if rOut.Value.SshTargetDetails.Password != nil {
		err = d.Set("password", *rOut.Value.SshTargetDetails.Password)
		if err != nil {
			return err
		}
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

	d.SetId(name)
	return nil
}
