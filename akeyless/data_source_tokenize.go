package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
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
				Description: "The encrypted result",
			},
		},
	}
}

func dataSourceTokenizeRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

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
		return common.HandleReadError(d, "can't tokenize", res, err)
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
