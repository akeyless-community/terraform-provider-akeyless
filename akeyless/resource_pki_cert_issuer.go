package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
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
				Optional:    true,
				Description: "A key to sign the certificate with, required in Private CA mode",
			},
			"ttl": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The maximum requested Time To Live for issued certificate by default in seconds, supported formats are s,m,h,d. In case of Public CA, this is based on the CA target's supported maximum TTLs",
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
			"allowed_ip_sans": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A list of the allowed CIDRs for IPs that clients can request to be included in the certificate as part of the IP Subject Alternative Names (in a comma-delimited list)",
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
			"critical_key_usage": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Mark key usage as critical [true/false]",
				Default:     "true",
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
			"is_ca": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, the basic constraints extension will be added to certificate",
			},
			"enable_acme": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, the cert issuer will support the acme protocol",
			},
			"expiration_event_in": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "How many days before the expiration of the certificate would you like to be notified",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"allowed_extra_extensions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A json string that defines the allowed extra extensions for the pki cert issuer",
			},
			"allow_copy_ext_from_csr": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, will allow copying the extra extensions from the csr file (if given)",
			},
			"create_public_crl": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Set this to allow the cert issuer will expose a public CRL endpoint",
			},
			"create_private_crl": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Set this to allow the issuer will expose a CRL endpoint in the Gateway",
			},
			"auto_renew": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Automatically renew certificates before expiration",
			},
			"scheduled_renew": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Number of days before expiration to renew certificates",
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
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	signerKeyName := d.Get("signer_key_name").(string)
	ttl := d.Get("ttl").(string)
	allowedDomains := d.Get("allowed_domains").(string)
	allowedUriSans := d.Get("allowed_uri_sans").(string)
	allowedIpSans := d.Get("allowed_ip_sans").(string)
	allowSubdomains := d.Get("allow_subdomains").(bool)
	notEnforceHostnames := d.Get("not_enforce_hostnames").(bool)
	allowAnyName := d.Get("allow_any_name").(bool)
	notRequireCn := d.Get("not_require_cn").(bool)
	serverFlag := d.Get("server_flag").(bool)
	clientFlag := d.Get("client_flag").(bool)
	codeSigningFlag := d.Get("code_signing_flag").(bool)
	keyUsage := d.Get("key_usage").(string)
	criticalKeyUsage := d.Get("critical_key_usage").(string)
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
	isCA := d.Get("is_ca").(bool)
	enableACME := d.Get("enable_acme").(bool)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	allowedExtraExtensions := d.Get("allowed_extra_extensions").(string)
	allowCopyExtFromCSR := d.Get("allow_copy_ext_from_csr").(bool)
	createPublicCRL := d.Get("create_public_crl").(bool)
	createPrivateCRL := d.Get("create_private_crl").(bool)
	autoRenew := d.Get("auto_renew").(bool)
	scheduledRenew := d.Get("scheduled_renew").(int)
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(bool)

	body := akeyless_api.CreatePKICertIssuer{
		Name:  name,
		Ttl:   ttl,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.SignerKeyName, signerKeyName)
	common.GetAkeylessPtr(&body.AllowedDomains, allowedDomains)
	common.GetAkeylessPtr(&body.AllowedUriSans, allowedUriSans)
	common.GetAkeylessPtr(&body.AllowedIpSans, allowedIpSans)
	common.GetAkeylessPtr(&body.AllowSubdomains, allowSubdomains)
	common.GetAkeylessPtr(&body.NotEnforceHostnames, notEnforceHostnames)
	common.GetAkeylessPtr(&body.AllowAnyName, allowAnyName)
	common.GetAkeylessPtr(&body.NotRequireCn, notRequireCn)
	common.GetAkeylessPtr(&body.ServerFlag, serverFlag)
	common.GetAkeylessPtr(&body.ClientFlag, clientFlag)
	common.GetAkeylessPtr(&body.CodeSigningFlag, codeSigningFlag)
	common.GetAkeylessPtr(&body.KeyUsage, keyUsage)
	common.GetAkeylessPtr(&body.CriticalKeyUsage, criticalKeyUsage)
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
	common.GetAkeylessPtr(&body.IsCa, isCA)
	common.GetAkeylessPtr(&body.EnableAcme, enableACME)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.AllowedExtraExtensions, allowedExtraExtensions)
	common.GetAkeylessPtr(&body.AllowCopyExtFromCsr, allowCopyExtFromCSR)
	common.GetAkeylessPtr(&body.CreatePublicCrl, createPublicCRL)
	common.GetAkeylessPtr(&body.CreatePrivateCrl, createPrivateCRL)
	common.GetAkeylessPtr(&body.AutoRenew, autoRenew)
	common.GetAkeylessPtr(&body.ScheduledRenew, scheduledRenew)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, strconv.FormatBool(deleteProtection))

	_, resp, err := client.CreatePKICertIssuer(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to create pki cert issuer", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourcePKICertIssuerRead(d *schema.ResourceData, m interface{}) error {
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
		err := d.Set("tags", rOut.ItemTags)
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
		assocs := rOut.ItemTargetsAssoc
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
			// if ttl represents seconds, it can contain or not contain - "s" at the end.
			outTtl := common.SecondsToTimeString(int(*certDetails.MaxTtl))
			ttlInState := d.Get("ttl").(string)
			if ttlInState != "" && !strings.HasSuffix(ttlInState, "s") {
				outTtl = strings.TrimSuffix(outTtl, "s")
			}

			err := d.Set("ttl", outTtl)
			if err != nil {
				return err
			}
		}

		if certDetails.PkiCertIssuerDetails != nil {
			pki := certDetails.PkiCertIssuerDetails

			if pki.AllowedDomainsList != nil {
				err := d.Set("allowed_domains", strings.Join(pki.AllowedDomainsList, ","))
				if err != nil {
					return err
				}
			}
			if pki.AllowedUriSans != nil {
				err := d.Set("allowed_uri_sans", strings.Join(pki.AllowedUriSans, ","))
				if err != nil {
					return err
				}
			}
			if pki.AllowedIpSans != nil {
				err := d.Set("allowed_ip_sans", strings.Join(pki.AllowedIpSans, ","))
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
				err := d.Set("key_usage", strings.Join(pki.KeyUsageList, ","))
				if err != nil {
					return err
				}
			}
			if pki.NonCriticalKeyUsage != nil {
				err := d.Set("critical_key_usage", strconv.FormatBool(!*pki.NonCriticalKeyUsage))
				if err != nil {
					return err
				}
			}
			if pki.OrganizationUnitList != nil {
				err := d.Set("organizational_units", strings.Join(pki.OrganizationUnitList, ","))
				if err != nil {
					return err
				}
			}
			if pki.OrganizationList != nil {
				err := d.Set("organizations", strings.Join(pki.OrganizationList, ","))
				if err != nil {
					return err
				}
			}
			if pki.Country != nil {
				err := d.Set("country", strings.Join(pki.Country, ","))
				if err != nil {
					return err
				}
			}
			if pki.Locality != nil {
				err := d.Set("locality", strings.Join(pki.Locality, ","))
				if err != nil {
					return err
				}
			}
			if pki.Province != nil {
				err := d.Set("province", strings.Join(pki.Province, ","))
				if err != nil {
					return err
				}
			}
			if pki.StreetAddress != nil {
				err := d.Set("street_address", strings.Join(pki.StreetAddress, ","))
				if err != nil {
					return err
				}
			}
			if pki.PostalCode != nil {
				err := d.Set("postal_code", strings.Join(pki.PostalCode, ","))
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
			if pki.IsCa != nil {
				err := d.Set("is_ca", *pki.IsCa)
				if err != nil {
					return err
				}
			}
			if pki.AcmeEnabled != nil {
				err := d.Set("enable_acme", *pki.AcmeEnabled)
				if err != nil {
					return err
				}
			}
			if pki.ExpirationEvents != nil {
				err := d.Set("expiration_event_in", common.ReadExpirationEventInParam(pki.ExpirationEvents))
				if err != nil {
					return err
				}
			}
			if pki.AllowedExtraExtensions != nil {
				extensions, err := getAllowedExtraExtensions(d.Get("allowed_extra_extensions").(string), *pki.AllowedExtraExtensions)
				if err != nil {
					return err
				}
				err = d.Set("allowed_extra_extensions", extensions)
				if err != nil {
					return err
				}
			}
			if pki.AllowCopyExtFromCsr != nil {
				err := d.Set("allow_copy_ext_from_csr", *pki.AllowCopyExtFromCsr)
				if err != nil {
					return err
				}
			}
			if pki.CreatePublicCrl != nil {
				err := d.Set("create_public_crl", *pki.CreatePublicCrl)
				if err != nil {
					return err
				}
			}
			if pki.CreatePrivateCrl != nil {
				err := d.Set("create_private_crl", *pki.CreatePrivateCrl)
				if err != nil {
					return err
				}
			}
			if pki.AutoRenewCertificate != nil {
				err := d.Set("auto_renew", *pki.AutoRenewCertificate)
				if err != nil {
					return err
				}
			}
			if pki.RenewBeforeExpirationInDays != nil {
				err := d.Set("scheduled_renew", *pki.RenewBeforeExpirationInDays)
				if err != nil {
					return err
				}
			}
		}
	}

	d.SetId(path)

	return nil
}

func getAllowedExtraExtensions(currentAee string, aee map[string][]string) (string, error) {
	currentAeeMap, err := convertStringToMapArr(currentAee)
	if err != nil {
		return "", err
	}

	if compareMaps(currentAeeMap, aee) {
		return currentAee, nil
	}

	return convertMapArrToString(aee)
}

func convertStringToMapArr(str string) (map[string][]string, error) {
	var m map[string][]string
	err := json.Unmarshal([]byte(str), &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func compareMaps(submitted, received map[string][]string) bool {
	if len(submitted) != len(received) {
		return false
	}

	for key, submittedValues := range submitted {
		receivedValues, exists := received[key]
		if !exists {
			return false
		}

		// Sort both slices and compare them
		sort.Strings(submittedValues)
		sort.Strings(receivedValues)

		if !reflect.DeepEqual(submittedValues, receivedValues) {
			return false
		}
	}

	return true
}

func convertMapArrToString(m map[string][]string) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func resourcePKICertIssuerUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	signerKeyName := d.Get("signer_key_name").(string)
	ttl := d.Get("ttl").(string)
	allowedDomains := d.Get("allowed_domains").(string)
	allowedUriSans := d.Get("allowed_uri_sans").(string)
	allowedIpSans := d.Get("allowed_ip_sans").(string)
	allowSubdomains := d.Get("allow_subdomains").(bool)
	notEnforceHostnames := d.Get("not_enforce_hostnames").(bool)
	allowAnyName := d.Get("allow_any_name").(bool)
	notRequireCn := d.Get("not_require_cn").(bool)
	serverFlag := d.Get("server_flag").(bool)
	clientFlag := d.Get("client_flag").(bool)
	codeSigningFlag := d.Get("code_signing_flag").(bool)
	keyUsage := d.Get("key_usage").(string)
	criticalKeyUsage := d.Get("critical_key_usage").(string)
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
	isCA := d.Get("is_ca").(bool)
	enableACME := d.Get("enable_acme").(bool)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	allowedExtraExtensions := d.Get("allowed_extra_extensions").(string)
	allowCopyExtFromCSR := d.Get("allow_copy_ext_from_csr").(bool)
	createPublicCRL := d.Get("create_public_crl").(bool)
	createPrivateCRL := d.Get("create_private_crl").(bool)
	autoRenew := d.Get("auto_renew").(bool)
	scheduledRenew := d.Get("scheduled_renew").(int)
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(bool)

	body := akeyless_api.UpdatePKICertIssuer{
		Name:  name,
		Ttl:   ttl,
		Token: &token,
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
	common.GetAkeylessPtr(&body.AllowedIpSans, allowedIpSans)
	common.GetAkeylessPtr(&body.AllowSubdomains, allowSubdomains)
	common.GetAkeylessPtr(&body.NotEnforceHostnames, notEnforceHostnames)
	common.GetAkeylessPtr(&body.AllowAnyName, allowAnyName)
	common.GetAkeylessPtr(&body.NotRequireCn, notRequireCn)
	common.GetAkeylessPtr(&body.ServerFlag, serverFlag)
	common.GetAkeylessPtr(&body.ClientFlag, clientFlag)
	common.GetAkeylessPtr(&body.CodeSigningFlag, codeSigningFlag)
	common.GetAkeylessPtr(&body.KeyUsage, keyUsage)
	common.GetAkeylessPtr(&body.CriticalKeyUsage, criticalKeyUsage)
	common.GetAkeylessPtr(&body.OrganizationalUnits, organizationalUnits)
	common.GetAkeylessPtr(&body.Organizations, organizations)
	common.GetAkeylessPtr(&body.Country, country)
	common.GetAkeylessPtr(&body.Locality, locality)
	common.GetAkeylessPtr(&body.Province, province)
	common.GetAkeylessPtr(&body.StreetAddress, streetAddress)
	common.GetAkeylessPtr(&body.PostalCode, postalCode)
	common.GetAkeylessPtr(&body.GwClusterUrl, gwClusterUrl)
	common.GetAkeylessPtr(&body.DestinationPath, destinationPath)
	common.GetAkeylessPtr(&body.IsCa, isCA)
	common.GetAkeylessPtr(&body.EnableAcme, enableACME)
	common.GetAkeylessPtr(&body.ProtectCertificates, protectCertificates)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.AllowedExtraExtensions, allowedExtraExtensions)
	common.GetAkeylessPtr(&body.AllowCopyExtFromCsr, allowCopyExtFromCSR)
	common.GetAkeylessPtr(&body.CreatePublicCrl, createPublicCRL)
	common.GetAkeylessPtr(&body.CreatePrivateCrl, createPrivateCRL)
	common.GetAkeylessPtr(&body.AutoRenew, autoRenew)
	common.GetAkeylessPtr(&body.ScheduledRenew, scheduledRenew)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, strconv.FormatBool(deleteProtection))

	_, resp, err := client.UpdatePKICertIssuer(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("failed to update pki cert issuer", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourcePKICertIssuerDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.DeleteItem{
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

	id := d.Id()

	err := resourcePKICertIssuerRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
