package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePKICertIssuer() *schema.Resource {
	return &schema.Resource{
		Description: "PKI Cert Issuer  resource",
		Create:      resourcePKICertIssuerCreate,
		Read:        resourcePKICertIssuerRead,
		Update:      resourcePKICertIssuerUpdate,
		Delete:      resourcePKICertIssuerDelete,
		Importer: &schema.ResourceImporter{
			State: resourcePKICertIssuerImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "PKI certificate issuer name",
				ForceNew:    true,
			},
			"signer_key_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A key to sign the certificate with",
			},
			"ttl": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "The maximum requested Time To Live for issued certificates, in seconds. In case of Public CA, this is based on the CA target's supported maximum TTLs",
			},
			"allowed_domains": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A list of the allowed domains that clients can request to be included in the certificate (in a comma-delimited list)",
			},
			"allowed_uri_sans": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A list of the allowed URIs that clients can request to be included in the certificate as part of the URI Subject Alternative Names (in a comma-delimited list)",
			},
			"allow_subdomains": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, clients can request certificates for subdomains and wildcard subdomains of the allowed domains",
			},
			"not_enforce_hostnames": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, any names are allowed for CN and SANs in the certificate and not only a valid host name",
			},
			"allow_any_name": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, clients can request certificates for any CN",
			},
			"not_require_cn": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, clients can request certificates without a CN",
			},
			"server_flag": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, certificates will be flagged for server auth use",
			},
			"client_flag": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, certificates will be flagged for client auth use",
			},
			"code_signing_flag": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, certificates will be flagged for code signing use",
			},
			"key_usage": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma-separated string or list of key usages",
				Default:     "DigitalSignature,KeyAgreement,KeyEncipherment",
			},
			"organizational_units": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma-separated list of organizational units (OU) that will be set in the issued certificate",
			},
			"organizations": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma-separated list of organizations (O) that will be set in the issued certificate",
			},
			"country": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma-separated list of countries that will be set in the issued certificate",
			},
			"locality": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma-separated list of localities that will be set in the issued certificate",
			},
			"province": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma-separated list of provinces that will be set in the issued certificate",
			},
			"street_address": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma-separated list of street addresses that will be set in the issued certificate",
			},
			"postal_code": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma-separated list of postal codes that will be set in the issued certificate",
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
			"ca_target": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of an existing CA target to attach this PKI Certificate Issuer to, required in Public CA mode",
			},
			"gw_cluster_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The GW cluster URL to issue the certificate from, required in Public CA mode",
			},
			"destination_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A path in Akeyless which to save generated certificates",
			},
			"protect_certificates": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether to protect generated certificates from deletion",
			},
			"expiration_event_in": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "How many days before the expiration of the certificate would you like to be notified",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Protection from accidental deletion of this item, [true/false]",
			},
		},
	}
}

func resourcePKICertIssuerCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	signerKeyName := d.Get("signer_key_name").(string)
	ttl := d.Get("ttl").(int)
	allowedDomains := d.Get("allowed_domains").(string)
	allowedUriSans := d.Get("allowed_uri_sans").(string)
	allowSubdomains := d.Get("allow_subdomains").(bool)
	notEnforceHostnames := d.Get("not_enforce_hostnames").(bool)
	allowAnyName := d.Get("allow_any_name").(bool)
	notRequireCn := d.Get("not_require_cn").(bool)
	serverFlag := d.Get("server_flag").(bool)
	clientFlag := d.Get("client_flag").(bool)
	codeSigningFlag := d.Get("code_signing_flag").(bool)
	keyUsage := d.Get("key_usage").(string)
	organizationalUnits := d.Get("organizational_units").(string)
	organizations := d.Get("organizations").(string)
	country := d.Get("country").(string)
	locality := d.Get("locality").(string)
	province := d.Get("province").(string)
	streetAddress := d.Get("street_address").(string)
	postalCode := d.Get("postal_code").(string)
	tagSet := d.Get("tags").(*schema.Set)
	tagsList := common.ExpandStringList(tagSet.List())
	caTarget := d.Get("ca_target").(string)
	gwClusterUrl := d.Get("gw_cluster_url").(string)
	destinationPath := d.Get("destination_path").(string)
	protectCertificates := d.Get("protect_certificates").(bool)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(bool)

	body := akeyless.CreatePKICertIssuer{
		Name:  name,
		Ttl:   int64(ttl),
		Token: &token,
	}
	common.GetAkeylessPtr(&body.SignerKeyName, signerKeyName)
	common.GetAkeylessPtr(&body.AllowedDomains, allowedDomains)
	common.GetAkeylessPtr(&body.AllowedUriSans, allowedUriSans)
	common.GetAkeylessPtr(&body.AllowSubdomains, allowSubdomains)
	common.GetAkeylessPtr(&body.NotEnforceHostnames, notEnforceHostnames)
	common.GetAkeylessPtr(&body.AllowAnyName, allowAnyName)
	common.GetAkeylessPtr(&body.NotRequireCn, notRequireCn)
	common.GetAkeylessPtr(&body.ServerFlag, serverFlag)
	common.GetAkeylessPtr(&body.ClientFlag, clientFlag)
	common.GetAkeylessPtr(&body.CodeSigningFlag, codeSigningFlag)
	common.GetAkeylessPtr(&body.KeyUsage, keyUsage)
	common.GetAkeylessPtr(&body.OrganizationalUnits, organizationalUnits)
	common.GetAkeylessPtr(&body.Organizations, organizations)
	common.GetAkeylessPtr(&body.Country, country)
	common.GetAkeylessPtr(&body.Locality, locality)
	common.GetAkeylessPtr(&body.Province, province)
	common.GetAkeylessPtr(&body.StreetAddress, streetAddress)
	common.GetAkeylessPtr(&body.PostalCode, postalCode)
	common.GetAkeylessPtr(&body.Tag, tagsList)
	common.GetAkeylessPtr(&body.CaTarget, caTarget)
	common.GetAkeylessPtr(&body.GwClusterUrl, gwClusterUrl)
	common.GetAkeylessPtr(&body.DestinationPath, destinationPath)
	common.GetAkeylessPtr(&body.ProtectCertificates, protectCertificates)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, strconv.FormatBool(deleteProtection))

	_, _, err := client.CreatePKICertIssuer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("failed to create pki cert issuer: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to create pki cert issuer: %w", err)
	}

	d.SetId(name)

	return nil
}

func resourcePKICertIssuerRead(d *schema.ResourceData, m interface{}) error {
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
			return fmt.Errorf("failed to get item: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to get item: %w", err)
	}

	if rOut.CertIssuerSignerKeyName != nil {
		err := d.Set("signer_key_name", *rOut.CertIssuerSignerKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.ItemMetadata != nil {
		err := d.Set("description", *rOut.ItemMetadata)
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
	if rOut.DeleteProtection != nil {
		err := d.Set("delete_protection", *rOut.DeleteProtection)
		if err != nil {
			return err
		}
	}
	if rOut.ItemTargetsAssoc != nil {
		assocs := *rOut.ItemTargetsAssoc
		if len(assocs) > 0 {
			assoc := assocs[0]
			if assoc.TargetName != nil {
				err := d.Set("ca_target", *assoc.TargetName)
				if err != nil {
					return err
				}
			}
		}
	}

	if rOut.CertificateIssueDetails != nil {
		certDetails := rOut.CertificateIssueDetails

		if certDetails.MaxTtl != nil {
			err := d.Set("ttl", *certDetails.MaxTtl)
			if err != nil {
				return err
			}
		}

		if certDetails.PkiCertIssuerDetails != nil {
			pki := certDetails.PkiCertIssuerDetails

			if pki.AllowedDomainsList != nil {
				err := d.Set("allowed_domains", strings.Join(*pki.AllowedDomainsList, ","))
				if err != nil {
					return err
				}
			}
			if pki.AllowedUriSans != nil {
				err := d.Set("allowed_uri_sans", strings.Join(*pki.AllowedUriSans, ","))
				if err != nil {
					return err
				}
			}
			if pki.AllowSubdomains != nil {
				err := d.Set("allow_subdomains", *pki.AllowSubdomains)
				if err != nil {
					return err
				}
			}
			if pki.EnforceHostnames != nil {
				err := d.Set("not_enforce_hostnames", !*pki.EnforceHostnames)
				if err != nil {
					return err
				}
			}
			if pki.AllowAnyName != nil {
				err := d.Set("allow_any_name", *pki.AllowAnyName)
				if err != nil {
					return err
				}
			}
			if pki.RequireCn != nil {
				err := d.Set("not_require_cn", !*pki.RequireCn)
				if err != nil {
					return err
				}
			}
			if pki.ServerFlag != nil {
				err := d.Set("server_flag", *pki.ServerFlag)
				if err != nil {
					return err
				}
			}
			if pki.ClientFlag != nil {
				err := d.Set("client_flag", *pki.ClientFlag)
				if err != nil {
					return err
				}
			}
			if pki.CodeSigningFlag != nil {
				err := d.Set("code_signing_flag", *pki.CodeSigningFlag)
				if err != nil {
					return err
				}
			}
			if pki.KeyUsageList != nil {
				err := d.Set("key_usage", strings.Join(*pki.KeyUsageList, ","))
				if err != nil {
					return err
				}
			}
			if pki.OrganizationUnitList != nil {
				err := d.Set("organizational_units", strings.Join(*pki.OrganizationUnitList, ","))
				if err != nil {
					return err
				}
			}
			if pki.OrganizationList != nil {
				err := d.Set("organizations", strings.Join(*pki.OrganizationList, ","))
				if err != nil {
					return err
				}
			}
			if pki.Country != nil {
				err := d.Set("country", strings.Join(*pki.Country, ","))
				if err != nil {
					return err
				}
			}
			if pki.Locality != nil {
				err := d.Set("locality", strings.Join(*pki.Locality, ","))
				if err != nil {
					return err
				}
			}
			if pki.Province != nil {
				err := d.Set("province", strings.Join(*pki.Province, ","))
				if err != nil {
					return err
				}
			}
			if pki.StreetAddress != nil {
				err := d.Set("street_address", strings.Join(*pki.StreetAddress, ","))
				if err != nil {
					return err
				}
			}
			if pki.PostalCode != nil {
				err := d.Set("postal_code", strings.Join(*pki.PostalCode, ","))
				if err != nil {
					return err
				}
			}
			if pki.GwClusterUrl != nil {
				err := d.Set("gw_cluster_url", *pki.GwClusterUrl)
				if err != nil {
					return err
				}
			}
			if pki.DestinationPath != nil {
				err := d.Set("destination_path", *pki.DestinationPath)
				if err != nil {
					return err
				}
			}
			if pki.ProtectGeneratedCertificates != nil {
				err := d.Set("protect_certificates", *pki.ProtectGeneratedCertificates)
				if err != nil {
					return err
				}
			}
			if pki.ExpirationEvents != nil {
				err := d.Set("expiration_event_in", readExpirationEventInParam(*pki.ExpirationEvents))
				if err != nil {
					return err
				}
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourcePKICertIssuerUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	signerKeyName := d.Get("signer_key_name").(string)
	ttl := d.Get("ttl").(int)
	allowedDomains := d.Get("allowed_domains").(string)
	allowedUriSans := d.Get("allowed_uri_sans").(string)
	allowSubdomains := d.Get("allow_subdomains").(bool)
	notEnforceHostnames := d.Get("not_enforce_hostnames").(bool)
	allowAnyName := d.Get("allow_any_name").(bool)
	notRequireCn := d.Get("not_require_cn").(bool)
	serverFlag := d.Get("server_flag").(bool)
	clientFlag := d.Get("client_flag").(bool)
	codeSigningFlag := d.Get("code_signing_flag").(bool)
	keyUsage := d.Get("key_usage").(string)
	organizationalUnits := d.Get("organizational_units").(string)
	organizations := d.Get("organizations").(string)
	country := d.Get("country").(string)
	locality := d.Get("locality").(string)
	province := d.Get("province").(string)
	streetAddress := d.Get("street_address").(string)
	postalCode := d.Get("postal_code").(string)
	tagSet := d.Get("tags").(*schema.Set)
	tagsList := common.ExpandStringList(tagSet.List())
	gwClusterUrl := d.Get("gw_cluster_url").(string)
	destinationPath := d.Get("destination_path").(string)
	protectCertificates := d.Get("protect_certificates").(bool)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(bool)

	body := akeyless.UpdatePKICertIssuer{
		Name:          name,
		SignerKeyName: signerKeyName,
		Ttl:           int64(ttl),
		Token:         &token,
	}
	add, remove, err := common.GetTagsForUpdate(d, name, token, tagsList, client)
	if err == nil {
		if len(add) > 0 {
			common.GetAkeylessPtr(&body.AddTag, add)
		}
		if len(remove) > 0 {
			common.GetAkeylessPtr(&body.RmTag, remove)
		}
	}
	common.GetAkeylessPtr(&body.AddTag, add)
	common.GetAkeylessPtr(&body.RmTag, remove)

	common.GetAkeylessPtr(&body.SignerKeyName, signerKeyName)
	common.GetAkeylessPtr(&body.AllowedDomains, allowedDomains)
	common.GetAkeylessPtr(&body.AllowedUriSans, allowedUriSans)
	common.GetAkeylessPtr(&body.AllowSubdomains, allowSubdomains)
	common.GetAkeylessPtr(&body.NotEnforceHostnames, notEnforceHostnames)
	common.GetAkeylessPtr(&body.AllowAnyName, allowAnyName)
	common.GetAkeylessPtr(&body.NotRequireCn, notRequireCn)
	common.GetAkeylessPtr(&body.ServerFlag, serverFlag)
	common.GetAkeylessPtr(&body.ClientFlag, clientFlag)
	common.GetAkeylessPtr(&body.CodeSigningFlag, codeSigningFlag)
	common.GetAkeylessPtr(&body.KeyUsage, keyUsage)
	common.GetAkeylessPtr(&body.OrganizationalUnits, organizationalUnits)
	common.GetAkeylessPtr(&body.Organizations, organizations)
	common.GetAkeylessPtr(&body.Country, country)
	common.GetAkeylessPtr(&body.Locality, locality)
	common.GetAkeylessPtr(&body.Province, province)
	common.GetAkeylessPtr(&body.StreetAddress, streetAddress)
	common.GetAkeylessPtr(&body.PostalCode, postalCode)
	common.GetAkeylessPtr(&body.GwClusterUrl, gwClusterUrl)
	common.GetAkeylessPtr(&body.DestinationPath, destinationPath)
	common.GetAkeylessPtr(&body.ProtectCertificates, protectCertificates)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, strconv.FormatBool(deleteProtection))

	_, _, err = client.UpdatePKICertIssuer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("failed to update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to update : %w", err)
	}

	d.SetId(name)

	return nil
}

func resourcePKICertIssuerDelete(d *schema.ResourceData, m interface{}) error {
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

func resourcePKICertIssuerImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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

func readExpirationEventInParam(expirationEvents []akeyless.CertificateExpirationEvent) []string {
	var expirationEventsList []string
	for _, e := range expirationEvents {
		seconds := e.GetSecondsBefore()
		days := seconds / 60 / 60 / 24
		expirationEventsList = append(expirationEventsList, strconv.FormatInt(days, 10))
	}
	return expirationEventsList
}
