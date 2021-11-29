package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePKICertIssuer() *schema.Resource {
	return &schema.Resource{
		Description: "PKI Cert Issuer resource",
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
				Description: "he requested Time To Live for the certificate, in seconds",
			},
			"allowed_domains": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A list of the allowed domains that clients can request to be included in the certificate (in a comma-delimited list)",
			},
			"allowed_uri_sans": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A list of the allowed URIs that clients can request to be included in the certificate as part of the URI Subject Alternative Names (in a comma-delimited list)",
			},
			"allow_subdomains": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "If set, clients can request certificates for subdomains and wildcard subdomains of the allowed domains",
			},
			"not_enforce_hostnames": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "If set, any names are allowed for CN and SANs in the certificate and not only a valid host name",
			},
			"allow_any_name": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "If set, clients can request certificates for any CN",
			},
			"not_require_cn": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "If set, clients can request certificates without a CN",
			},
			"server_flag": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "If set, certificates will be flagged for server auth use",
			},
			"client_flag": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "If set, certificates will be flagged for client auth use",
			},
			"code_signing_flag": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "If set, certificates will be flagged for code signing use",
			},
			"key_usage": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A comma-separated string or list of key usages",
				Default:     "DigitalSignature,KeyAgreement,KeyEncipherment",
			},
			"organizational_units": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A comma-separated list of organizational units (OU) that will be set in the issued certificate",
			},
			"organizations": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A comma-separated list of organizations (O) that will be set in the issued certificate",
			},
			"country": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A comma-separated list of the country that will be set in the issued certificate",
			},
			"locality": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A comma-separated list of the locality that will be set in the issued certificate",
			},
			"province": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A comma-separated list of the province that will be set in the issued certificate",
			},
			"street_address": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A comma-separated list of the street address that will be set in the issued certificate",
			},
			"postal_code": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A comma-separated list of the postal code that will be set in the issued certificate",
			},
			"metadata": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "A metadata about the issuer",
			},
			"tag": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this key. To specify multiple tags use argument multiple times: --tag Tag1 --tag Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
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
	metadata := d.Get("metadata").(string)
	tagSet := d.Get("tag").(*schema.Set)
	tag := common.ExpandStringList(tagSet.List())

	body := akeyless.  CreatePKICertIssuer{
		Name:          name,
		SignerKeyName: signerKeyName,
		Ttl:           ttl,
		Token:         &token,
	}
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
	common.GetAkeylessPtr(&body.Metadata, metadata)
	common.GetAkeylessPtr(&body.Tag, tag)

	_, _, err := client.CreatePKICertIssuer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
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
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}

	/*
	   // TODO fix this
	   	if rOut.Name != nil {
	   		err = d.Set("name", *rOut.Name)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.SignerKeyName != nil {
	   		err = d.Set("signer_key_name", *rOut.SignerKeyName)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.Ttl != nil {
	   		err = d.Set("ttl", *rOut.Ttl)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.AllowedDomains != nil {
	   		err = d.Set("allowed_domains", *rOut.AllowedDomains)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.AllowedUriSans != nil {
	   		err = d.Set("allowed_uri_sans", *rOut.AllowedUriSans)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.AllowSubdomains != nil {
	   		err = d.Set("allow_subdomains", *rOut.AllowSubdomains)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.NotEnforceHostnames != nil {
	   		err = d.Set("not_enforce_hostnames", *rOut.NotEnforceHostnames)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.AllowAnyName != nil {
	   		err = d.Set("allow_any_name", *rOut.AllowAnyName)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.NotRequireCn != nil {
	   		err = d.Set("not_require_cn", *rOut.NotRequireCn)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.ServerFlag != nil {
	   		err = d.Set("server_flag", *rOut.ServerFlag)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.ClientFlag != nil {
	   		err = d.Set("client_flag", *rOut.ClientFlag)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.CodeSigningFlag != nil {
	   		err = d.Set("code_signing_flag", *rOut.CodeSigningFlag)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.KeyUsage != nil {
	   		err = d.Set("key_usage", *rOut.KeyUsage)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.OrganizationalUnits != nil {
	   		err = d.Set("organizational_units", *rOut.OrganizationalUnits)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.Organizations != nil {
	   		err = d.Set("organizations", *rOut.Organizations)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.Country != nil {
	   		err = d.Set("country", *rOut.Country)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.Locality != nil {
	   		err = d.Set("locality", *rOut.Locality)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.Province != nil {
	   		err = d.Set("province", *rOut.Province)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.StreetAddress != nil {
	   		err = d.Set("street_address", *rOut.StreetAddress)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.PostalCode != nil {
	   		err = d.Set("postal_code", *rOut.PostalCode)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.Metadata != nil {
	   		err = d.Set("metadata", *rOut.Metadata)
	   		if err != nil {
	   			return err
	   		}
	   	}
	   	if rOut.Tag != nil {
	   		err = d.Set("tag", *rOut.Tag)
	   		if err != nil {
	   			return err
	   		}
	   	}

	   	common.GetSra(d, path, token, client)

	*/

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
	metadata := d.Get("metadata").(string)
	tagSet := d.Get("tag").(*schema.Set)
	tag := common.ExpandStringList(tagSet.List())

	body := akeyless.CreatePKICertIssuer{
		Name:          name,
		SignerKeyName: signerKeyName,
		Ttl:           ttl,
		Token:         &token,
	}
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
	common.GetAkeylessPtr(&body.Metadata, metadata)
	common.GetAkeylessPtr(&body.Tag, tag)

	_, _, err := client.CreatePKICertIssuer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
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
