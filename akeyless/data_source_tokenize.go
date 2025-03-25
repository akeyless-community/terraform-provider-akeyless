package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceTokenize() *schema.Resource {
	return &schema.Resource{
		Description: "Encrypts text with a tokenizer data source",
		Read:        dataSourceTokenizeRead,
		Schema: map[string]*schema.Schema{
			"tokenizer_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the tokenizer to use in the encryption process",
			},
			"plaintext": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Data to be encrypted",
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

func dataSourceTokenizeRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	tokenizerName := d.Get("tokenizer_name").(string)
	plaintext := d.Get("plaintext").(string)
	tweak := d.Get("tweak").(string)

	body := akeyless_api.Tokenize{
		TokenizerName: tokenizerName,
		Plaintext:     plaintext,
		Token:         &token,
	}
	common.GetAkeylessPtr(&body.Tweak, tweak)

	rOut, res, err := client.Tokenize(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't tokenize: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't tokenize: %v", err)
	}
	err = d.Set("result", *rOut.Result)
	if err != nil {
		return err
	}
	if rOut.Tweak != nil {
		err = d.Set("tweak", *rOut.Tweak)
		if err != nil {
			return err
		}
	}

	d.SetId(tokenizerName)
	return nil
}
