// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceTokenizer() *schema.Resource {
	return &schema.Resource{
		Description: "Tokenizer resource",
		Create:      resourceTokenizerCreate,
		Read:        resourceTokenizerRead,
		Update:      resourceTokenizerUpdate,
		Delete:      resourceTokenizerDelete,
		Importer: &schema.ResourceImporter{
			State: resourceTokenizerImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Tokenizer name",
				ForceNew:    true,
			},
			"tokenizer_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "vaultless",
				Description: "Tokenizer type(vaultless)",
			},
			"template_type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Which template type this tokenizer is used for [SSN,CreditCard,USPhoneNumber,Custom]",
			},
			"encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AES key name to use in vaultless tokenization",
			},
			"tweak_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The tweak type to use in vaultless tokenization [Supplied, Generated, Internal, Masking]",
			},
			"alphabet": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Alphabet to use in custom vaultless tokenization, such as '0123456789' for credit cards.",
			},
			"pattern": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Pattern to use in custom vaultless tokenization",
			},
			"encoding_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Encoding output template to use in custom vaultless tokenization",
			},
			"decoding_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Decoding output template to use in custom vaultless tokenization",
			},
			"tweak": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "",
			},
			"metadata": {
				Type:        schema.TypeString,
				Optional:    true,
				Deprecated:  "Deprecated: Use description instead",
				Description: "A metadata about the tokenizer",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"tag": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this key. To specify multiple tags use argument multiple times: --tag Tag1 --tag Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "false",
				Description: "Protection from accidental deletion of this item, [true/false]",
			},
		},
	}
}

func resourceTokenizerCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	tokenizerType := d.Get("tokenizer_type").(string)
	templateType := d.Get("template_type").(string)
	encryptionKeyName := d.Get("encryption_key_name").(string)
	tweakType := d.Get("tweak_type").(string)
	alphabet := d.Get("alphabet").(string)
	pattern := d.Get("pattern").(string)
	encodingTemplate := d.Get("encoding_template").(string)
	decodingTemplate := d.Get("decoding_template").(string)
	description := common.GetItemDescription(d)
	tagSet := d.Get("tag").(*schema.Set)
	tag := common.ExpandStringList(tagSet.List())
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless.CreateTokenizer{
		Name:          name,
		TokenizerType: tokenizerType,
		TemplateType:  templateType,
		Token:         &token,
	}
	common.GetAkeylessPtr(&body.EncryptionKeyName, encryptionKeyName)
	common.GetAkeylessPtr(&body.TweakType, tweakType)
	common.GetAkeylessPtr(&body.Alphabet, alphabet)
	common.GetAkeylessPtr(&body.Pattern, pattern)
	common.GetAkeylessPtr(&body.EncodingTemplate, encodingTemplate)
	common.GetAkeylessPtr(&body.DecodingTemplate, decodingTemplate)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tag, tag)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.CreateTokenizer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create tokenizer: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create tokenizer: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceTokenizerRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.DescribeItem{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't get tokenizer: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get tokenizer: %v", err)
	}

	if rOut.ItemType != nil && *rOut.ItemType == "VAULTLESS_TOK" {
		*rOut.ItemType = "vaultless"
	}
	err = d.Set("tokenizer_type", rOut.ItemType)
	if err != nil {
		return err
	}

	itemInfo := rOut.ItemGeneralInfo
	if itemInfo != nil {

		tokenizerInfo := itemInfo.TokenizerInfo
		if tokenizerInfo != nil {

			vaultlessTokenizerInfo := tokenizerInfo.VaultlessTokenizerInfo
			if vaultlessTokenizerInfo != nil {

				if vaultlessTokenizerInfo.KeyName != nil {
					err = d.Set("encryption_key_name", *vaultlessTokenizerInfo.KeyName)
					if err != nil {
						return err
					}
				}
				if vaultlessTokenizerInfo.TemplateType != nil {
					err = d.Set("template_type", *vaultlessTokenizerInfo.TemplateType)
					if err != nil {
						return err
					}
				}
				if vaultlessTokenizerInfo.Tweak != nil {
					err = d.Set("tweak", string(*vaultlessTokenizerInfo.Tweak))
					if err != nil {
						return err
					}
				}
				if vaultlessTokenizerInfo.TweakType != nil {
					err = d.Set("tweak_type", *vaultlessTokenizerInfo.TweakType)
					if err != nil {
						return err
					}
				}

				regexpTokenizerInfo := vaultlessTokenizerInfo.RegexpTokenizerInfo
				if regexpTokenizerInfo != nil {
					if regexpTokenizerInfo.Alphabet != nil {
						err = d.Set("alphabet", *regexpTokenizerInfo.Alphabet)
						if err != nil {
							return err
						}
					}
					if regexpTokenizerInfo.Pattern != nil {
						err = d.Set("pattern", *regexpTokenizerInfo.Pattern)
						if err != nil {
							return err
						}
					}
					if regexpTokenizerInfo.EncodingTemplate != nil {
						err = d.Set("encoding_template", *regexpTokenizerInfo.EncodingTemplate)
						if err != nil {
							return err
						}
					}
					if regexpTokenizerInfo.DecodingTemplate != nil {
						err = d.Set("decoding_template", *regexpTokenizerInfo.DecodingTemplate)
						if err != nil {
							return err
						}
					}
				}
			}
		}
	}

	if rOut.ItemMetadata != nil {
		err := common.SetDescriptionBc(d, *rOut.ItemMetadata)
		if err != nil {
			return err
		}
	}
	if rOut.ItemTags != nil {
		err = d.Set("tag", *rOut.ItemTags)
		if err != nil {
			return err
		}
	}
	if rOut.DeleteProtection != nil {
		err = d.Set("delete_protection", strconv.FormatBool(*rOut.DeleteProtection))
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceTokenizerUpdate(d *schema.ResourceData, m interface{}) error {

	err := validateTokenizerUpdateParams(d)
	if err != nil {
		return fmt.Errorf("can't update: %v", err)
	}

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	description := common.GetItemDescription(d)
	tagSet := d.Get("tag").(*schema.Set)
	tagList := common.ExpandStringList(tagSet.List())
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless.UpdateItem{
		Name:             name,
		DeleteProtection: &deleteProtection,
		Token:            &token,
	}

	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.NewMetadata, common.DefaultMetadata)

	add, remove, err := common.GetTagsForUpdate(d, name, token, tagList, client)
	if err == nil {
		if len(add) > 0 {
			common.GetAkeylessPtr(&body.AddTag, add)
		}
		if len(remove) > 0 {
			common.GetAkeylessPtr(&body.RmTag, remove)
		}
	}

	_, _, err = client.UpdateItem(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update tokenizer: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update tokenizer: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceTokenizerDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteItem{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteItem(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceTokenizerImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.DescribeItem{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func validateTokenizerUpdateParams(d *schema.ResourceData) error {
	paramsMustNotUpdate := []string{"tokenizer_type", "template_type",
		"encryption_key_name", "tweak_type", "alphabet", "pattern",
		"encoding_template", "decoding_template"}
	return common.GetErrorOnUpdateParam(d, paramsMustNotUpdate)
}
