package akeyless

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAuthMethodCert() *schema.Resource {
	return &schema.Resource{
		Description: "Cert Auth Method Resource",
		Create:      resourceAuthMethodCertCreate,
		Read:        resourceAuthMethodCertRead,
		Update:      resourceAuthMethodCertUpdate,
		Delete:      resourceAuthMethodCertDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodCertImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Auth Method name",
				ForceNew:         true,
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"unique_identifier": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A unique identifier (ID) value should be configured for OIDC, OAuth2, LDAP and SAML authentication method types and is usually a value such as the email, username, or upn for example. Whenever a user logs in with a token, these authentication types issue a sub claim that contains details uniquely identifying that user. This sub claim includes a key containing the ID value that you configured, and is used to distinguish between different users from within the same organization.",
			},
			"access_expires": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Access expiration date in Unix timestamp (select 0 for access without expiry date)",
				Default:     "0",
			},
			"bound_ips": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A comma-separated CIDR block list to allow client access",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"gw_bound_ips": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A comma-separated CIDR block list as a trusted Gateway entity",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"force_sub_claims": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "enforce role-association must include sub claims",
			},
			"jwt_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Creds expiration time in minutes",
				Default:     0,
			},
			"certificate_data": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The certificate data in base64, if no file was provided.",
			},
			"bound_common_names": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of names. At least one must exist in the Common Name. Supports globbing.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_dns_sans": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of DNS names. At least one must exist in the SANs. Supports globbing.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_email_sans": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of Email Addresses. At least one must exist in the SANs. Supports globbing.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_uri_sans": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of URIs. At least one must exist in the SANs. Supports globbing.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_organizational_units": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of Organizational Units names. At least one must exist in the OU field.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"bound_extensions": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of extensions formatted as 'oid:value'. Expects the extension value to be some type of ASN1 encoded string. All values much match. Supports globbing on 'value'.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"revoked_cert_ids": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "A list of revoked cert ids",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"audit_logs_claims": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Subclaims to include in audit logs",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this auth method, [true/false]",
				Default:     "false",
			},
			"access_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Auth Method access ID",
			},
		},
	}
}

func resourceAuthMethodCertCreate(d *schema.ResourceData, m interface{}) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	uniqueIdentifier := d.Get("unique_identifier").(string)
	accessExpires := d.Get("access_expires").(int)
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	gwBoundIpsSet := d.Get("gw_bound_ips").(*schema.Set)
	gwBoundIps := common.ExpandStringList(gwBoundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	jwtTtl := d.Get("jwt_ttl").(int)
	certificateData := d.Get("certificate_data").(string)
	boundCommonNamesSet := d.Get("bound_common_names").(*schema.Set)
	boundCommonNames := common.ExpandStringList(boundCommonNamesSet.List())
	boundDnsSansSet := d.Get("bound_dns_sans").(*schema.Set)
	boundDnsSans := common.ExpandStringList(boundDnsSansSet.List())
	boundEmailSansSet := d.Get("bound_email_sans").(*schema.Set)
	boundEmailSans := common.ExpandStringList(boundEmailSansSet.List())
	boundUriSansSet := d.Get("bound_uri_sans").(*schema.Set)
	boundUriSans := common.ExpandStringList(boundUriSansSet.List())
	boundOrganizationalUnitsSet := d.Get("bound_organizational_units").(*schema.Set)
	boundOrganizationalUnits := common.ExpandStringList(boundOrganizationalUnitsSet.List())
	boundExtensionsSet := d.Get("bound_extensions").(*schema.Set)
	boundExtensions := common.ExpandStringList(boundExtensionsSet.List())
	revokedCertIdsSet := d.Get("revoked_cert_ids").(*schema.Set)
	revokedCertIds := common.ExpandStringList(revokedCertIdsSet.List())
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)

	certificateData = base64.StdEncoding.EncodeToString([]byte(certificateData))

	body := akeyless_api.AuthMethodCreateCert{
		Name:             name,
		UniqueIdentifier: uniqueIdentifier,
		Token:            &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.CertificateData, certificateData)
	common.GetAkeylessPtr(&body.BoundCommonNames, boundCommonNames)
	common.GetAkeylessPtr(&body.BoundDnsSans, boundDnsSans)
	common.GetAkeylessPtr(&body.BoundEmailSans, boundEmailSans)
	common.GetAkeylessPtr(&body.BoundUriSans, boundUriSans)
	common.GetAkeylessPtr(&body.BoundOrganizationalUnits, boundOrganizationalUnits)
	common.GetAkeylessPtr(&body.BoundExtensions, boundExtensions)
	common.GetAkeylessPtr(&body.RevokedCertIds, revokedCertIds)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	rOut, res, err := client.AuthMethodCreateCert(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("failed to create auth method cert: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Auth Method cert: %v", err)
	}

	if rOut.AccessId != nil {
		err = d.Set("access_id", *rOut.AccessId)
		if err != nil {
			return err
		}
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodCertRead(d *schema.ResourceData, m interface{}) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.AuthMethodGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.AuthMethodGet(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("failed to get value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to get value: %w", err)
	}

	if rOut.AccessInfo != nil {
		accessInfo := *rOut.AccessInfo
		if accessInfo.AccessExpires != nil {
			err = d.Set("access_expires", *accessInfo.AccessExpires)
			if err != nil {
				return err
			}
		}
		if accessInfo.ForceSubClaims != nil {
			err = d.Set("force_sub_claims", *accessInfo.ForceSubClaims)
			if err != nil {
				return err
			}
		}

		rOutAcc, err := getAccountSettings(m)
		if err != nil {
			return err
		}
		jwtDefault := extractAccountJwtTtlDefault(rOutAcc)

		if accessInfo.JwtTtl != nil {
			if *accessInfo.JwtTtl != jwtDefault || d.Get("jwt_ttl").(int) != 0 {
				err = d.Set("jwt_ttl", *accessInfo.JwtTtl)
				if err != nil {
					return err
				}
			}
		}
		if accessInfo.CidrWhitelist != nil && *accessInfo.CidrWhitelist != "" {
			err = d.Set("bound_ips", strings.Split(*accessInfo.CidrWhitelist, ","))
			if err != nil {
				return err
			}
		}
		if accessInfo.GwCidrWhitelist != nil && *accessInfo.GwCidrWhitelist != "" {
			err = d.Set("gw_bound_ips", strings.Split(*accessInfo.GwCidrWhitelist, ","))
			if err != nil {
				return err
			}
		}
		if accessInfo.AuditLogsClaims != nil {
			err = d.Set("audit_logs_claims", accessInfo.AuditLogsClaims)
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
		if accessInfo.CertAccessRules != nil {
			certAccessRules := accessInfo.CertAccessRules
			if certAccessRules.UniqueIdentifier != nil {
				err = d.Set("unique_identifier", *certAccessRules.UniqueIdentifier)
				if err != nil {
					return err
				}
			}
			if certAccessRules.BoundCommonNames != nil {
				err = d.Set("bound_common_names", certAccessRules.BoundCommonNames)
				if err != nil {
					return err
				}
			}
			if certAccessRules.BoundDnsSans != nil {
				err = d.Set("bound_dns_sans", certAccessRules.BoundDnsSans)
				if err != nil {
					return err
				}
			}
			if certAccessRules.BoundEmailSans != nil {
				err = d.Set("bound_email_sans", certAccessRules.BoundEmailSans)
				if err != nil {
					return err
				}
			}
			if certAccessRules.BoundUriSans != nil {
				err = d.Set("bound_uri_sans", certAccessRules.BoundUriSans)
				if err != nil {
					return err
				}
			}
			if certAccessRules.BoundOrganizationalUnits != nil {
				err = d.Set("bound_organizational_units", certAccessRules.BoundOrganizationalUnits)
				if err != nil {
					return err
				}
			}
			if certAccessRules.BoundExtensions != nil {
				err = d.Set("bound_extensions", certAccessRules.BoundExtensions)
				if err != nil {
					return err
				}
			}
			if certAccessRules.RevokedCertIds != nil {
				err = d.Set("revoked_cert_ids", certAccessRules.RevokedCertIds)
				if err != nil {
					return err
				}
			}
			if certAccessRules.Certificate != nil {

				certData := *certAccessRules.Certificate
				if !isBase64Encoded(certData) {
					certData = base64.StdEncoding.EncodeToString([]byte(certData))
				}

				err = d.Set("certificate_data", certData)
				if err != nil {
					return err
				}
			}
		}
	}

	d.SetId(path)

	return nil
}

func isBase64Encoded(data string) bool {
	_, err := base64.StdEncoding.DecodeString(data)
	return err == nil
}

func resourceAuthMethodCertUpdate(d *schema.ResourceData, m interface{}) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	uniqueIdentifier := d.Get("unique_identifier").(string)
	accessExpires := d.Get("access_expires").(int)
	boundIpsSet := d.Get("bound_ips").(*schema.Set)
	boundIps := common.ExpandStringList(boundIpsSet.List())
	gwBoundIpsSet := d.Get("gw_bound_ips").(*schema.Set)
	gwBoundIps := common.ExpandStringList(gwBoundIpsSet.List())
	forceSubClaims := d.Get("force_sub_claims").(bool)
	jwtTtl := d.Get("jwt_ttl").(int)
	certificateData := d.Get("certificate_data").(string)
	boundCommonNamesSet := d.Get("bound_common_names").(*schema.Set)
	boundCommonNames := common.ExpandStringList(boundCommonNamesSet.List())
	boundDnsSansSet := d.Get("bound_dns_sans").(*schema.Set)
	boundDnsSans := common.ExpandStringList(boundDnsSansSet.List())
	boundEmailSansSet := d.Get("bound_email_sans").(*schema.Set)
	boundEmailSans := common.ExpandStringList(boundEmailSansSet.List())
	boundUriSansSet := d.Get("bound_uri_sans").(*schema.Set)
	boundUriSans := common.ExpandStringList(boundUriSansSet.List())
	boundOrganizationalUnitsSet := d.Get("bound_organizational_units").(*schema.Set)
	boundOrganizationalUnits := common.ExpandStringList(boundOrganizationalUnitsSet.List())
	boundExtensionsSet := d.Get("bound_extensions").(*schema.Set)
	boundExtensions := common.ExpandStringList(boundExtensionsSet.List())
	revokedCertIdsSet := d.Get("revoked_cert_ids").(*schema.Set)
	revokedCertIds := common.ExpandStringList(revokedCertIdsSet.List())
	subClaimsSet := d.Get("audit_logs_claims").(*schema.Set)
	subClaims := common.ExpandStringList(subClaimsSet.List())
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.AuthMethodUpdateCert{
		Name:             name,
		UniqueIdentifier: uniqueIdentifier,
		Token:            &token,
	}
	common.GetAkeylessPtr(&body.AccessExpires, accessExpires)
	common.GetAkeylessPtr(&body.BoundIps, boundIps)
	common.GetAkeylessPtr(&body.GwBoundIps, gwBoundIps)
	common.GetAkeylessPtr(&body.ForceSubClaims, forceSubClaims)
	common.GetAkeylessPtr(&body.JwtTtl, jwtTtl)
	common.GetAkeylessPtr(&body.CertificateData, certificateData)
	common.GetAkeylessPtr(&body.BoundCommonNames, boundCommonNames)
	common.GetAkeylessPtr(&body.BoundDnsSans, boundDnsSans)
	common.GetAkeylessPtr(&body.BoundEmailSans, boundEmailSans)
	common.GetAkeylessPtr(&body.BoundUriSans, boundUriSans)
	common.GetAkeylessPtr(&body.BoundOrganizationalUnits, boundOrganizationalUnits)
	common.GetAkeylessPtr(&body.BoundExtensions, boundExtensions)
	common.GetAkeylessPtr(&body.RevokedCertIds, revokedCertIds)
	common.GetAkeylessPtr(&body.AuditLogsClaims, subClaims)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.AuthMethodUpdateCert(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("failed to update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("failed to update : %w", err)
	}

	d.SetId(name)

	return nil
}

func resourceAuthMethodCertDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.AuthMethodDelete{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.AuthMethodDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceAuthMethodCertImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAuthMethodCertRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
