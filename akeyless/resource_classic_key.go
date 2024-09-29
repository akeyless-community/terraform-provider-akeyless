// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceClassicKey() *schema.Resource {
	return &schema.Resource{
		Description: "Classic Key resource",
		Create:      resourceClassicKeyCreate,
		Read:        resourceClassicKeyRead,
		Update:      resourceClassicKeyUpdate,
		Delete:      resourceClassicKeyDelete,
		Importer: &schema.ResourceImporter{
			State: resourceClassicKeyImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Classic key name",
				ForceNew:    true,
			},
			"alg": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Key type; options: [AES128GCM, AES256GCM, AES128SIV, AES256SIV, AES128CBC, AES256CBC, RSA1024, RSA2048, RSA3072, RSA4096, EC256, EC384, GPG]",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this key",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"key_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Base64-encoded classic key value provided by user",
			},
			"cert_file_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PEM Certificate in a Base64 format.",
			},
			"gpg_alg": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "gpg alg: Relevant only if GPG key type selected; options: [RSA1024, RSA2048, RSA3072, RSA4096, Ed25519]",
			},
			"protection_key_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "The name of the key that protects the classic key value (if empty, the account default key will be used)",
			},
			"generate_self_signed_certificate": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether to generate a self signed certificate with the key. If set, certificate_ttl must be provided.",
				Default:     "false",
			},
			"certificate_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "TTL in days for the generated certificate. Required only for generate-self-signed-certificate.",
				Default:     0,
			},
			"certificate_common_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Common name for the generated certificate. Relevant only for generate-self-signed-certificate.",
			},
			"certificate_organization": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Organization name for the generated certificate. Relevant only for generate-self-signed-certificate.",
			},
			"certificate_country": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Country name for the generated certificate. Relevant only for generate-self-signed-certificate.",
			},
			"certificate_locality": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Locality for the generated certificate. Relevant only for generate-self-signed-certificate.",
			},
			"certificate_province": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Province name for the generated certificate. Relevant only for generate-self-signed-certificate.",
			},
			"conf_file_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The csr config data in base64 encoding",
			},
			"certificate_format": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The format of the returned certificate [pem/der]",
				Default:     "pem",
			},
			"expiration_event_in": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "How many days before the expiration of the certificate would you like to be notified.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"auto_rotate": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to automatically rotate every --rotation-interval days, or disable existing automatic rotation [true/false]",
				Default:     "false",
			},
			"rotation_interval": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The number of days to wait between every automatic rotation (1-365)",
				Default:     "90",
			},
			"rotation_event_in": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "How many days before the rotation of the item would you like to be notified.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "Protection from accidental deletion of this object, [true/false]",
			},
		},
	}
}

func resourceClassicKeyCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	alg := d.Get("alg").(string)
	keyData := d.Get("key_data").(string)
	certFileData := d.Get("cert_file_data").(string)
	gpgAlg := d.Get("gpg_alg").(string)
	protectionKeyName := d.Get("protection_key_name").(string)
	generateSelfSignedCertificate := d.Get("generate_self_signed_certificate").(bool)
	certificateTtl := d.Get("certificate_ttl").(int)
	certificateCommonName := d.Get("certificate_common_name").(string)
	certificateOrganization := d.Get("certificate_organization").(string)
	certificateCountry := d.Get("certificate_country").(string)
	certificateLocality := d.Get("certificate_locality").(string)
	certificateProvince := d.Get("certificate_province").(string)
	confFileData := d.Get("conf_file_data").(string)
	certificateFormat := d.Get("certificate_format").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	autoRotate := d.Get("auto_rotate").(string)
	rotationInterval := d.Get("rotation_interval").(string)
	rotationEventInSet := d.Get("rotation_event_in").(*schema.Set)
	rotationEventIn := common.ExpandStringList(rotationEventInSet.List())
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.CreateClassicKey{
		Name:  name,
		Alg:   alg,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.KeyData, keyData)
	common.GetAkeylessPtr(&body.CertFileData, certFileData)
	common.GetAkeylessPtr(&body.GpgAlg, gpgAlg)
	common.GetAkeylessPtr(&body.ProtectionKeyName, protectionKeyName)
	common.GetAkeylessPtr(&body.GenerateSelfSignedCertificate, generateSelfSignedCertificate)
	common.GetAkeylessPtr(&body.CertificateTtl, certificateTtl)
	common.GetAkeylessPtr(&body.CertificateCommonName, certificateCommonName)
	common.GetAkeylessPtr(&body.CertificateOrganization, certificateOrganization)
	common.GetAkeylessPtr(&body.CertificateCountry, certificateCountry)
	common.GetAkeylessPtr(&body.CertificateLocality, certificateLocality)
	common.GetAkeylessPtr(&body.CertificateProvince, certificateProvince)
	common.GetAkeylessPtr(&body.ConfFileData, confFileData)
	common.GetAkeylessPtr(&body.CertificateFormat, certificateFormat)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.AutoRotate, autoRotate)
	common.GetAkeylessPtr(&body.RotationInterval, rotationInterval)
	common.GetAkeylessPtr(&body.RotationEventIn, rotationEventIn)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.CreateClassicKey(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceClassicKeyRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DescribeItem{
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
			return fmt.Errorf("failed to get key: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to get key: %w", err)
	}

	if rOut.ItemTags != nil {
		err = d.Set("tags", *rOut.ItemTags)
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
	if rOut.ProtectionKeyName != nil {
		err = d.Set("protection_key_name", *rOut.ProtectionKeyName)
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
	if rOut.AutoRotate != nil {
		err = d.Set("auto_rotate", strconv.FormatBool(*rOut.AutoRotate))
		if err != nil {
			return err
		}
	}
	if rOut.RotationInterval != nil {
		err = d.Set("rotation_interval", strconv.FormatInt(*rOut.RotationInterval, 10))
		if err != nil {
			return err
		}
	}
	if rOut.ItemGeneralInfo != nil {
		if rOut.ItemGeneralInfo.ClassicKeyDetails != nil {
			classicKeyDetails := *rOut.ItemGeneralInfo.ClassicKeyDetails

			if classicKeyDetails.KeyType != nil {
				alg, gpgAlg := getAlg(classicKeyDetails.KeyType)
				err := d.Set("alg", alg)
				if err != nil {
					return err
				}
				err = d.Set("gpg_alg", gpgAlg)
				if err != nil {
					return err
				}
			}
		}
		if rOut.ItemGeneralInfo.CertificatesTemplateInfo != nil {
			certTemplateInfo := *rOut.ItemGeneralInfo.CertificatesTemplateInfo

			if certTemplateInfo.SelfSignedEnabled != nil {
				err := d.Set("generate_self_signed_certificate", *certTemplateInfo.SelfSignedEnabled)
				if err != nil {
					return err
				}
			}
			if certTemplateInfo.Ttl != nil {
				err := d.Set("certificate_ttl", *certTemplateInfo.Ttl)
				if err != nil {
					return err
				}
			}
			if certTemplateInfo.CommonName != nil {
				err := d.Set("certificate_common_name", *certTemplateInfo.CommonName)
				if err != nil {
					return err
				}
			}
			if certTemplateInfo.Organization != nil {
				err := d.Set("certificate_organization", *certTemplateInfo.Organization)
				if err != nil {
					return err
				}
			}
			if certTemplateInfo.Country != nil {
				err := d.Set("certificate_country", *certTemplateInfo.Country)
				if err != nil {
					return err
				}
			}
			if certTemplateInfo.Locality != nil {
				err := d.Set("certificate_locality", *certTemplateInfo.Locality)
				if err != nil {
					return err
				}
			}
			if certTemplateInfo.Province != nil {
				err := d.Set("certificate_province", *certTemplateInfo.Province)
				if err != nil {
					return err
				}
			}
		}
		if rOut.ItemGeneralInfo.CertificateFormat != nil {
			err := d.Set("certificate_format", *rOut.ItemGeneralInfo.CertificateFormat)
			if err != nil {
				return err
			}
		}
		if rOut.ItemGeneralInfo.ExpirationEvents != nil {
			err := d.Set("expiration_event_in", common.ReadExpirationEventInParam(*rOut.ItemGeneralInfo.ExpirationEvents))
			if err != nil {
				return err
			}
		}
		if rOut.ItemGeneralInfo.NextRotationEvents != nil {
			err := d.Set("rotation_event_in", common.ReadRotationEventInParam(*rOut.ItemGeneralInfo.NextRotationEvents))
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceClassicKeyUpdate(d *schema.ResourceData, m interface{}) error {

	err := validateClassicKeyUpdateParams(d)
	if err != nil {
		return fmt.Errorf("failed to update: %w", err)
	}

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tagList := common.ExpandStringList(tagsSet.List())
	deleteProtection := d.Get("delete_protection").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventInList := common.ExpandStringList(expirationEventInSet.List())

	body := akeyless_api.UpdateItem{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventInList)

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
			return fmt.Errorf("failed to update key: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to update key: %w", err)
	}

	err = common.UpdateRotationSettings(d, name, token, client)
	if err != nil {
		return err
	}

	d.SetId(name)

	return nil
}

func resourceClassicKeyDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.DeleteItem{
		Token:             &token,
		Name:              path,
		DeleteImmediately: akeyless_api.PtrBool(true),
		DeleteInDays:      akeyless_api.PtrInt64(-1),
	}

	ctx := context.Background()
	_, _, err := client.DeleteItem(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}
	return nil
}

func resourceClassicKeyImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceClassicKeyRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func getAlg(keyType *string) (*string, *string) {
	gpg := "GPG"
	if kType, isGpg := strings.CutPrefix(*keyType, gpg); isGpg {
		return &gpg, &kType
	}
	return keyType, nil
}

func validateClassicKeyUpdateParams(d *schema.ResourceData) error {
	paramsMustNotUpdate := []string{"alg", "gpg_alg",
		"generate_self_signed_certificate", "certificate_ttl",
		"certificate_common_name", "certificate_organization",
		"certificate_country", "certificate_locality", "certificate_province",
		"conf_file_data", "certificate_format"}
	return common.GetErrorOnUpdateParam(d, paramsMustNotUpdate)
}
