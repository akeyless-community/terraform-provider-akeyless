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

func dataSourceDetokenize() *schema.Resource {
	return &schema.Resource{
		Description: "Decrypts text with a tokenizer data source",
		Read:        dataSourceDetokenizeRead,
		Schema: map[string]*schema.Schema{
			"tokenizer_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the tokenizer to use in the decryption process",
			},
			"ciphertext": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Data to be decrypted",
			},
			"tweak": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Base64 encoded tweak for vaultless encryption",
			},
			"result": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "",
			},
		},
	}
}

func dataSourceDetokenizeRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	tokenizerName := d.Get("tokenizer_name").(string)
	ciphertext := d.Get("ciphertext").(string)
	tweak := d.Get("tweak").(string)

	body := akeyless_api.Detokenize{
		TokenizerName: tokenizerName,
		Ciphertext:    ciphertext,
		Token:         &token,
	}
	common.GetAkeylessPtr(&body.Tweak, tweak)

	rOut, res, err := client.Detokenize(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't detokenize: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't detokenize: %v", err)
	}
	err = d.Set("result", *rOut.Result)
	if err != nil {
		return err
	}

	d.SetId(tokenizerName)
	return nil
}
