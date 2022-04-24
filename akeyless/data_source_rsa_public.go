package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v2"
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
			"raw": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
			},
			"ssh": {
				Type:        schema.TypeString,
				Computed:    true,
				Required:    false,
				Description: "",
				//Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceGetRSAPublicRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Get("name").(string)

	ctx := context.Background()
	var apiErr akeyless.GenericOpenAPIError

	body := akeyless.GetRSAPublic{
		Name:  name,
		Token: &token,
	}

	rOut, res, err := client.GetRSAPublic(ctx).Body(body).Execute()

	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			err = json.Unmarshal(apiErr.Body(), &rOut)
			if err != nil {
				return fmt.Errorf("can't get value: %v", string(apiErr.Body()))
			}
		}
		if err != nil {
			return fmt.Errorf("can't get value: %v", err)
		}
	}
	if rOut.Raw != nil {
		err = d.Set("raw", *rOut.Raw)
		if err != nil {
			return err
		}
	}
	if rOut.Ssh != nil {
		err = d.Set("ssh", string(*rOut.Ssh))
		if err != nil {
			return err
		}
	}

	d.SetId(name)
	return nil
}
