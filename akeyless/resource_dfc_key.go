package akeyless

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDfcKey() *schema.Resource {
	return &schema.Resource{
		Description: "DFC Key resource ",
		Create:      resourceDfcKeyCreate,
		Read:        resourceDfcKeyRead,
		Update:      resourceDfcKeyUpdate,
		Delete:      resourceDfcKeyDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDfcKeyImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "DFCKey name",
				ForceNew:    true,
			},
			"alg": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "DFCKey type; options: [AES128GCM, AES256GCM, AES128SIV, AES256SIV, AES128CBC, AES256CBC, RSA1024, RSA2048, RSA3072, RSA4096]",
			},
			"metadata": {
				Type:       schema.TypeString,
				Optional:   true,
				Deprecated: "Deprecated: Use description instead",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this DFC key",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"split_level": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The number of fragments that the item will be split into (not includes customer fragment)",
				Default:     3,
			},
			"customer_frg_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The customer fragment ID that will be used to create the DFC key (if empty, the key will be created independently of a customer fragment)",
			},
			"generate_self_signed_certificate": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to generate a self signed certificate with the key. If set, certificate-ttl must be provided.",
			},
			"certificate_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "TTL in days for the generated certificate. Required only for generate-self-signed-certificate.",
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
			"cert_data_base64": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "PEM Certificate in a Base64 format. Used for updating RSA keys' certificates",
			},
			"delete_protection": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Protection from accidental deletion of this item, [true/false]",
			},
		},
	}
}

func resourceDfcKeyCreate(d *schema.ResourceData, m interface{}) error {

	err := validateDfcKeyCreateParams(d)
	if err != nil {
		return err
	}

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	alg := d.Get("alg").(string)
	description := common.GetItemDescription(d)
	tagSet := d.Get("tags").(*schema.Set)
	tag := common.ExpandStringList(tagSet.List())
	splitLevel := d.Get("split_level").(int)
	customerFrgId := d.Get("customer_frg_id").(string)
	generateSelfSignedCertificate := d.Get("generate_self_signed_certificate").(bool)
	certificateTtl := d.Get("certificate_ttl").(int)
	certificateCommonName := d.Get("certificate_common_name").(string)
	certificateOrganization := d.Get("certificate_organization").(string)
	certificateCountry := d.Get("certificate_country").(string)
	certificateLocality := d.Get("certificate_locality").(string)
	certificateProvince := d.Get("certificate_province").(string)
	deleteProtection := d.Get("delete_protection").(bool)

	body := akeyless.CreateDFCKey{
		Name:  name,
		Alg:   alg,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tag, tag)
	common.GetAkeylessPtr(&body.SplitLevel, splitLevel)
	common.GetAkeylessPtr(&body.CustomerFrgId, customerFrgId)
	common.GetAkeylessPtr(&body.GenerateSelfSignedCertificate, generateSelfSignedCertificate)
	common.GetAkeylessPtr(&body.CertificateTtl, certificateTtl)
	common.GetAkeylessPtr(&body.CertificateCommonName, certificateCommonName)
	common.GetAkeylessPtr(&body.CertificateOrganization, certificateOrganization)
	common.GetAkeylessPtr(&body.CertificateCountry, certificateCountry)
	common.GetAkeylessPtr(&body.CertificateLocality, certificateLocality)
	common.GetAkeylessPtr(&body.CertificateProvince, certificateProvince)
	common.GetAkeylessPtr(&body.DeleteProtection, strconv.FormatBool(deleteProtection))

	_, _, err = client.CreateDFCKey(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("failed to create key: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to create key: %w", err)
	}

	d.SetId(name)

	return nil
}

func resourceDfcKeyRead(d *schema.ResourceData, m interface{}) error {

	path := d.Id()

	rOut, err := getDfcKey(d, m)
	if err != nil || rOut == nil {
		return err
	}

	if rOut.ItemMetadata != nil {
		err := common.SetDescriptionBc(d, *rOut.ItemMetadata)
		if err != nil {
			return err
		}
	}

	if rOut.ItemType != nil {
		err := d.Set("alg", *rOut.ItemType)
		if err != nil {
			return err
		}
	}

	if rOut.ItemTags != nil {
		err := d.Set("tags", *rOut.ItemTags)
		if err != nil {
			return err
		}
	}
	if rOut.CustomerFragmentId != nil {
		err := d.Set("customer_frg_id", *rOut.CustomerFragmentId)
		if err != nil {
			return err
		}
	}
	if rOut.Certificates != nil {

		cert, err := encodeCertificate(*rOut.Certificates)
		if err != nil {
			return fmt.Errorf("failed to encode certificate: %w", err)
		}

		err = d.Set("cert_data_base64", cert)
		if err != nil {
			return err
		}
	}
	if rOut.DeleteProtection != nil {
		err := d.Set("delete_protection", *rOut.DeleteProtection)
		if err != nil {
			return err
		}
	}
	if rOut.ItemGeneralInfo != nil {
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
	}

	d.SetId(path)

	return nil
}

func resourceDfcKeyUpdate(d *schema.ResourceData, m interface{}) error {

	err := validateDfcKeyUpdateParams(d)
	if err != nil {
		return fmt.Errorf("failed to update: %w", err)
	}

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	description := common.GetItemDescription(d)
	tagSet := d.Get("tags").(*schema.Set)
	tagList := common.ExpandStringList(tagSet.List())
	certData := d.Get("cert_data_base64").(string)
	deleteProtection := d.Get("delete_protection").(bool)

	body := akeyless.UpdateItem{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.NewMetadata, common.DefaultMetadata)
	common.GetAkeylessPtr(&body.CertFileData, certData)
	common.GetAkeylessPtr(&body.DeleteProtection, strconv.FormatBool(deleteProtection))

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

	d.SetId(name)

	return nil
}

func resourceDfcKeyDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteItem{
		Token:             &token,
		Name:              path,
		DeleteImmediately: akeyless.PtrBool(true),
		DeleteInDays:      akeyless.PtrInt64(-1),
	}

	ctx := context.Background()
	_, _, err := client.DeleteItem(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceDfcKeyImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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

func getDfcKey(d *schema.ResourceData, m interface{}) (*akeyless.Item, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()
	if path == "" {
		path = d.Get("name").(string)
	}

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
				return nil, nil
			}
			return nil, fmt.Errorf("failed to get key: %v", string(apiErr.Body()))
		}
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return &rOut, nil
}

func encodeCertificate(cert string) (string, error) {
	if cert == "" {
		return "", nil
	}

	decoded, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return "", fmt.Errorf("failed to decode certificate: %w", err)
	}
	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: decoded,
	}

	certBytes := pem.EncodeToMemory(&block)
	return base64.StdEncoding.EncodeToString(certBytes), nil
}

func validateDfcKeyCreateParams(d *schema.ResourceData) error {
	paramMustNotCreate := "cert_data_base64"
	certData := d.Get(paramMustNotCreate).(string)
	if certData != "" {
		return fmt.Errorf("%s is not allowed in creation", paramMustNotCreate)
	}
	return nil
}

func validateDfcKeyUpdateParams(d *schema.ResourceData) error {
	paramsMustNotUpdate := []string{"alg", "split_level", "customer_frg_id",
		"generate_self_signed_certificate", "certificate_ttl",
		"certificate_common_name", "certificate_organization",
		"certificate_country", "certificate_locality", "certificate_province"}
	return common.GetErrorOnUpdateParam(d, paramsMustNotUpdate)
}
