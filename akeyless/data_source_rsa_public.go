package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGetRSAPublic() *schema.Resource {
	return &schema.Resource{
		Description: "Obtain the public key from a specific RSA private key data source",
		Read:        dataSourceGetRSAPublicRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of RSA key to extract the public key from",
				ForceNew:    true,
			},
			"pem": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "PEM formatted public key",
			},
			"raw": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "Raw format of the public key",
			},
			"ssh": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "SSH format of the public key",
			},
		},
	}
}

func dataSourceGetRSAPublicRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Get("name").(string)

	ctx := context.Background()
	var apiErr akeyless_api.GenericOpenAPIError

	body := akeyless_api.GetRSAPublic{
		Name:  name,
		Token: &token,
	}

	var out rsaPublicOutput
	var sshVal string
	var rawVal string
	var pemVal string

	rOut, res, err := client.GetRSAPublic(ctx).Body(body).Execute()

	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			err = json.Unmarshal(apiErr.Body(), &out)
			if err != nil {
				return fmt.Errorf("can't get value: %v", string(apiErr.Body()))
			}

			if out.Raw != nil && out.Ssh != nil {
				rawVal = *out.Raw
				sshVal = *out.Ssh
			} else {
				return fmt.Errorf("can't get value: raw or ssh key")
			}
			if out.Pem != nil {
				pemVal = *out.Pem
			}
		}
		if err != nil {
			return fmt.Errorf("can't get value: %v", err)
		}
	} else {
		rawVal = string(*rOut.Raw)
		sshVal = string(*rOut.Ssh)
		if rOut.Pem != nil {
			pemVal = string(*rOut.Pem)
		}
	}

	if rOut.Pem != nil {
		err = d.Set("pem", pemVal)
		if err != nil {
			return err
		}
	}
	if rOut.Raw != nil {
		err = d.Set("raw", rawVal)
		if err != nil {
			return err
		}
	}
	if rOut.Ssh != nil {
		err = d.Set("ssh", sshVal)
		if err != nil {
			return err
		}
	}

	d.SetId(name)
	return nil
}

type rsaPublicOutput struct {
	Pem *string `json:"pem,omitempty"`
	Raw *string `json:"raw,omitempty"`
	Ssh *string `json:"ssh,omitempty"`
}
