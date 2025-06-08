// generated file
package akeyless

import (
	"context"
	"encoding/base64"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceCertificate() *schema.Resource {
	return &schema.Resource{
		Description: "Certificate Resource",
		Create:      resourceCertificateCreate,
		Read:        resourceCertificateRead,
		Update:      resourceCertificateUpdate,
		Delete:      resourceCertificateDelete,
		Importer: &schema.ResourceImporter{
			State: resourceCertificateImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Certificate name",
				ForceNew:    true,
			},
			"certificate_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Computed:    true,
				Description: "Content of the certificate in a Base64 format.",
			},
			"format": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "CertificateFormat of the certificate and private key, possible values: cer,crt,pem,pfx,p12.",
				Default:     "pem",
			},
			"key_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Content of the certificate's private key in a Base64 format.",
			},
			"expiration_event_in": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "How many days before the expiration of the certificate would you like to be notified.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The name of a key to use to encrypt the certificate's key (if empty, the account default protectionKey key will be used)",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object. To specify multiple tags use argument multiple times: --tag Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Protection from accidental deletion of this object, [true/false]",
			},
		},
	}
}

func resourceCertificateCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	certificateData := d.Get("certificate_data").(string)
	format := d.Get("format").(string)
	keyData := d.Get("key_data").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	key := d.Get("key").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.CreateCertificate{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.CertificateData, certificateData)
	common.GetAkeylessPtr(&body.Format, format)
	common.GetAkeylessPtr(&body.KeyData, keyData)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, resp, err := client.CreateCertificate(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Certificate", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceCertificateRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	name := d.Id()

	body := akeyless_api.DescribeItem{
		Name:  name,
		Token: &token,
	}

	rOut, resp, err := client.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get Certificate", resp, err)
	}

	if rOut.ItemGeneralInfo != nil {
		if rOut.ItemGeneralInfo.CertificateChainInfo != nil {
			// We don't read the certificate format as it might change as it is derived from the certificate data.
			//if rOut.ItemGeneralInfo.CertificateChainInfo.CertificateFormat != nil {
			//	err = d.Set("format", *rOut.ItemGeneralInfo.CertificateChainInfo.CertificateFormat)
			//	if err != nil {
			//		return err
			//	}
			//}
			if rOut.ItemGeneralInfo.CertificateChainInfo.ExpirationEvents != nil {
				err = d.Set("expiration_event_in", common.ReadExpirationEventInParam(rOut.ItemGeneralInfo.CertificateChainInfo.ExpirationEvents))
				if err != nil {
					return err
				}
			}
		}
	}
	if rOut.ProtectionKeyName != nil {
		err = d.Set("key", *rOut.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.ItemTags != nil {
		err = d.Set("tags", rOut.ItemTags)
		if err != nil {
			return err
		}
	}
	if rOut.ItemMetadata != nil {
		err = d.Set("description", *rOut.ItemMetadata)
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

	certBody := akeyless_api.GetCertificateValue{
		Name:  &name,
		Token: &token,
	}

	certOut, resp, err := client.GetCertificateValue(ctx).Body(certBody).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get Certificate value", resp, err)
	}

	if certOut.CertificatePem != nil {
		err = d.Set("certificate_data", base64.StdEncoding.EncodeToString([]byte(*certOut.CertificatePem)))
		if err != nil {
			return err
		}
	}

	if certOut.PrivateKeyPem != nil {
		err = d.Set("key_data", base64.StdEncoding.EncodeToString([]byte(*certOut.PrivateKeyPem)))
		if err != nil {
			return err
		}
	}

	d.SetId(name)

	return nil
}

func resourceCertificateUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	certificateData := d.Get("certificate_data").(string)
	format := d.Get("format").(string)
	keyData := d.Get("key_data").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	key := d.Get("key").(string)
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless_api.UpdateCertificateValue{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.CertificateData, certificateData)
	common.GetAkeylessPtr(&body.Format, format)
	common.GetAkeylessPtr(&body.KeyData, keyData)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.Key, key)

	_, resp, err := client.UpdateCertificateValue(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update Certificate", resp, err)
	}

	updateBody := akeyless_api.UpdateItem{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&updateBody.Description, description)
	common.GetAkeylessPtr(&updateBody.DeleteProtection, deleteProtection)

	add, remove, err := common.GetTagsForUpdate(d, name, token, tags, client)
	if err == nil {
		if len(add) > 0 {
			common.GetAkeylessPtr(&updateBody.AddTag, add)
		}
		if len(remove) > 0 {
			common.GetAkeylessPtr(&updateBody.RmTag, remove)
		}
	}

	_, resp, err = client.UpdateItem(ctx).Body(updateBody).Execute()
	if err != nil {
		return common.HandleError("can't update Certificate details", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceCertificateDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Id()

	deleteItem := akeyless_api.DeleteItem{
		Token: &token,
		Name:  name,
	}

	ctx := context.Background()
	_, _, err := client.DeleteItem(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceCertificateImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()

	err := resourceCertificateRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
