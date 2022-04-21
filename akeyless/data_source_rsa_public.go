package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	// "akeyless.io/akeyless-main-repo/go/src/client/utils"
	// "golang.org/x/crypto/ssh"
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
				Type:        schema.TypeSet,
				Computed:    true,
				Required:    false,
				Description: "",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceGetRSAPublicRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	fmt.Println("--- in dataSourceGetRSAPublicRead ---")

	name := d.Get("name").(string)

	fmt.Println("|||| name:", name)

	ctx := context.Background()
	var apiErr akeyless.GenericOpenAPIError

	body := akeyless.GetRSAPublic{
		Name:  name,
		Token: &token,
	}

	rOut, res, err := client.GetRSAPublic(ctx).Body(body).Execute()

	fmt.Println("|||| rOut:", rOut)
	fmt.Println("|||| res:", res)
	fmt.Println("|||| err:", err)
	fmt.Println("|||| rOut.RAW:", rOut.GetRaw())
	fmt.Println("|||| rOut.SSH:", string(rOut.GetSsh()))

	if err != nil {
		if errors.As(err, &apiErr) {

			fmt.Println("|||| apiErr.Body:", string(apiErr.Body()))

			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			err = json.Unmarshal(apiErr.Body(), &rOut)

			fmt.Println("|||| rOut:", rOut)
			// fmt.Println("|||| rOut:", *rOut.Raw)
			// fmt.Println("|||| rOut:", (*rOut.Ssh)[0])
			fmt.Println("|||| rOut.RAW:", rOut.GetRaw())
			fmt.Println("|||| rOut.SSH:", rOut.GetSsh())

			if err != nil {
				fmt.Println("--- error 1 ---")
				return fmt.Errorf("can't get value: %v", string(apiErr.Body()))
			}
		}
		if err != nil {
			fmt.Println("--- error 2 ---")
			return fmt.Errorf("can't get value: %v", err)
		}
	}
	if rOut.Raw != nil {
		err = d.Set("raw", rOut.GetRaw())
		if err != nil {
			return err
		}
	}
	if rOut.Ssh != nil {
		// publicKey, err := utils.ExtractRSAPubKey(rOut.GetRaw())

		// pk, err := ssh.NewPublicKey(publicKey)
		if err != nil {
			return fmt.Errorf("failed to create SSH key: %w", err)
		}

		// pubBytes := ssh.MarshalAuthorizedKey(pk)

		// err = d.Set("ssh", pubBytes)
		// if err != nil {
		// 	return err
		// }
	}

	d.SetId(name)
	return nil
}
