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

func resourceAuthMethod() *schema.Resource {
	return &schema.Resource{
		Description: "Authentication Methods represent machine identities or human identities",
		Create:      resourceAuthMethodCreate,
		Read:        resourceAuthMethodRead,
		Update:      resourceAuthMethodUpdate,
		Delete:      resourceAuthMethodDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAuthMethodImport,
		},
		DeprecationMessage: "Deprecated: Please use new resource: akeyless_auth_method_<TYPE>",
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path where the Auth Method will be stored",
			},
			"bound_ips": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A CIDR whitelist with the IPs that the access is restricted to",
			},
			"access_expires": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Access expiration date in Unix timestamp (select 0 for access without expiry date)",
				Default:     0,
			},
			"access_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Auth Method access ID",
			},
			"access_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Auth Method access key",
			},
			"api_key": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A configuration block, described below, using API-Key Auth Method",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{},
				},
			},
			"saml": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A configuration block, described below, using SAML Auth Method",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"idp_metadata_url": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "IDP metadata url",
						},
						"idp_metadata_xml_data": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "IDP metadata xml data",
						},
						"unique_identifier": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "A unique identifier (ID) value should be configured for OAuth2, LDAP and SAML authentication method types and is usually a value such as the email, username, or upn for example",
						},
					},
				},
			},
			"aws_iam": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A configuration block, described below, using AWS-IAM Auth Method",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"sts_url": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "STS URL (default: https://sts.amazonaws.com)",
							Default:     "https://sts.amazonaws.com",
						},
						"bound_aws_account_id": {
							Type:        schema.TypeSet,
							Required:    true,
							Description: "A list of AWS account-IDs that the access is restricted to",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_arn": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of full arns that the access is restricted to",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_role_name": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of full role-name that the access is restricted to",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_role_id": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of full role ids that the access is restricted to",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_resource_id": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of full resource ids that the access is restricted to",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_user_name": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of full user-name that the access is restricted to",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_user_id": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of full user ids that the access is restricted to",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},
			"azure_ad": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A configuration block, described below, using Azure AD Auth Method",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"bound_tenant_id": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The Azure tenant id that the access is restricted to",
						},
						"jwks_uri": {
							Type:        schema.TypeString,
							Optional:    true,
							Default:     "https://login.microsoftonline.com/common/discovery/keys",
							Description: "The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server",
						},
						"custom_audience": {
							Type:        schema.TypeString,
							Optional:    true,
							Default:     "https://management.azure.com/",
							Description: "The audience in the JWT",
						},
						"custom_issuer": {
							Type:        schema.TypeString,
							Optional:    true,
							Default:     "https://sts.windows.net/",
							Description: "Issuer URL",
						},
						"bound_spid": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of service principal IDs that the access is restricted to",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_group_id": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of group ids that the access is restricted to",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_sub_id": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of subscription ids that the access is restricted to",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_rg_id": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of resource groups that the access is restricted to",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_providers": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc)",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_resource_types": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc)",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_resource_names": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc)",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
						"bound_resource_id": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "A list of full resource ids that the access is restricted to",
							MinItems:    1,
							Elem:        &schema.Schema{Type: schema.TypeString},
						},
					},
				},
			},
			"gcp": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A configuration block, described below, using Auth Method API-Key",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"audience": {
							Type:        schema.TypeString,
							Optional:    true,
							Default:     "akeyless.io",
							Description: "The audience to verify in the JWT received by the client",
						},
						"service_account_creds_data": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Service Account creds data, base64 encoded",
						},
						"iam": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "IAM GCP Auth Method",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"bound_service_accounts": {
										Type:        schema.TypeSet,
										Optional:    true,
										Description: "IAM only. A list of Service Accounts. Clients must belong to any of the provided service accounts in order to authenticate",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
						"gce": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "IAM GCE Auth Method",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"bound_labels": {
										Type:        schema.TypeSet,
										Optional:    true,
										Description: "GCE only. A list of GCP labels formatted as \"key:value\" pairs that must be set on instances in order to authenticate",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
									"bound_regions": {
										Type:        schema.TypeSet,
										Optional:    true,
										Description: "GCE only. A list of regions. GCE instances must belong to any of the provided regions in order to authenticate",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
									"bound_zones": {
										Type:        schema.TypeSet,
										Optional:    true,
										Description: "GCE only. A list of zones. GCE instances must belong to any of the provided zones in order to authenticate",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func resourceAuthMethodUpdate(d *schema.ResourceData, m interface{}) error {
	return resourceAuthMethodRead(d, m)
}

func resourceAuthMethodCreate(d *schema.ResourceData, m interface{}) error {
	var apiErr akeyless.GenericOpenAPIError
	err := createAuthMethod(d, m)
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create auth method: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't auth method: %v", err)
	}

	return nil
}

func resourceAuthMethodDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteAuthMethod{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteAuthMethod(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceAuthMethodRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Get("path").(string)

	body := akeyless.GetAuthMethod{
		Name:  path,
		Token: &token,
	}
	_, res, err := client.GetAuthMethod(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The secret was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't get Auth Method: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't Auth Method: %v", err)
	}

	return nil
}

func resourceAuthMethodImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GetAuthMethod{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GetAuthMethod(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("path", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func createAuthMethod(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token
	ctx := context.Background()

	var boundIpsList []string

	path := d.Get("path").(string)
	boundIps, ok := d.Get("bound_ips").(*schema.Set)
	if ok {
		boundIpsList = common.ExpandStringList(boundIps.List())
	}
	accessExpires := int64(d.Get("access_expires").(int))

	apiKeyAuthMethod := d.Get("api_key").([]interface{})
	if apiKeyAuthMethod != nil && len(apiKeyAuthMethod) == 1 {
		body := akeyless.CreateAuthMethod{
			Name:          path,
			BoundIps:      &boundIpsList,
			AccessExpires: &accessExpires,
			Token:         &token,
		}
		apiKey, _, err := client.CreateAuthMethod(ctx).Body(body).Execute()
		if err != nil {
			return err
		}

		err = d.Set("access_id", apiKey.AccessId)
		if err != nil {
			return err
		}
		err = d.Set("access_key", apiKey.AccessKey)
		if err != nil {
			return err
		}

		d.SetId(path)
		return nil
	}

	samlAuthMethod := d.Get("saml").([]interface{})
	if samlAuthMethod != nil && len(samlAuthMethod) == 1 {
		saml := samlAuthMethod[0].(map[string]interface{})
		idpMetadataUrl := saml["idp_metadata_url"].(string)
		idpMetadataXmlData := saml["idp_metadata_xml_data"].(string)
		uniqueIdentifier := saml["unique_identifier"].(string)
		body := akeyless.CreateAuthMethodSAML{
			Name:               path,
			BoundIps:           &boundIpsList,
			AccessExpires:      &accessExpires,
			IdpMetadataUrl:     akeyless.PtrString(idpMetadataUrl),
			IdpMetadataXmlData: akeyless.PtrString(idpMetadataXmlData),
			UniqueIdentifier:   uniqueIdentifier,
			Token:              &token,
		}
		apiKey, _, err := client.CreateAuthMethodSAML(ctx).Body(body).Execute()
		if err != nil {
			return err
		}
		err = d.Set("access_id", apiKey.AccessId)
		if err != nil {
			return err
		}
		d.SetId(path)
		return nil
	}

	awsAuthMethod := d.Get("aws_iam").([]interface{})
	if awsAuthMethod != nil && len(awsAuthMethod) == 1 {
		aws := awsAuthMethod[0].(map[string]interface{})
		boundAwsAccountId := aws["bound_aws_account_id"].(*schema.Set)
		boundAwsAccountIdList := common.ExpandStringList(boundAwsAccountId.List())
		boundArn := aws["bound_arn"].(*schema.Set)
		boundArnList := common.ExpandStringList(boundArn.List())

		stsURL := aws["sts_url"].(string)
		boundRoleName := aws["bound_role_name"].(*schema.Set)
		boundRoleNameList := common.ExpandStringList(boundRoleName.List())

		boundResourceID := aws["bound_resource_id"].(*schema.Set)
		boundResourceIDList := common.ExpandStringList(boundResourceID.List())

		boundUserName := aws["bound_user_name"].(*schema.Set)
		boundUserNameList := common.ExpandStringList(boundUserName.List())

		boundUserID := aws["bound_user_id"].(*schema.Set)
		boundUserIDList := common.ExpandStringList(boundUserID.List())

		body := akeyless.CreateAuthMethodAWSIAM{
			Name:              path,
			BoundIps:          &boundIpsList,
			AccessExpires:     &accessExpires,
			StsUrl:            akeyless.PtrString(stsURL),
			BoundAwsAccountId: boundAwsAccountIdList,
			BoundArn:          &boundArnList,
			BoundRoleName:     &boundRoleNameList,
			BoundUserId:       &boundUserIDList,
			BoundUserName:     &boundUserNameList,
			BoundResourceId:   &boundResourceIDList,
			Token:             &token,
		}
		apiKey, _, err := client.CreateAuthMethodAWSIAM(ctx).Body(body).Execute()
		if err != nil {
			return err
		}
		err = d.Set("access_id", apiKey.AccessId)
		if err != nil {
			return err
		}
		d.SetId(path)
		return nil
	}

	azureAuthMethod := d.Get("azure_ad").([]interface{})
	if azureAuthMethod != nil && len(azureAuthMethod) == 1 {
		azure := azureAuthMethod[0].(map[string]interface{})
		boundTenantId := azure["bound_tenant_id"].(string)
		jwksUri := azure["jwks_uri"].(string)
		issuer := azure["custom_issuer"].(string)
		audience := azure["custom_audience"].(string)

		boundSpid := azure["bound_spid"].(*schema.Set)
		boundSpidList := common.ExpandStringList(boundSpid.List())

		boundGroupID := azure["bound_group_id"].(*schema.Set)
		boundGroupIDList := common.ExpandStringList(boundGroupID.List())

		boundSubID := azure["bound_sub_id"].(*schema.Set)
		boundSubIDList := common.ExpandStringList(boundSubID.List())

		boundRgID := azure["bound_rg_id"].(*schema.Set)
		boundRgIDList := common.ExpandStringList(boundRgID.List())

		boundProviders := azure["bound_providers"].(*schema.Set)
		boundProvidersList := common.ExpandStringList(boundProviders.List())

		boundResourceTypes := azure["bound_resource_types"].(*schema.Set)
		boundResourceTypesList := common.ExpandStringList(boundResourceTypes.List())

		boundResourceNames := azure["bound_resource_names"].(*schema.Set)
		boundResourceNamesList := common.ExpandStringList(boundResourceNames.List())

		boundResourceID := azure["bound_resource_id"].(*schema.Set)
		boundResourceIDList := common.ExpandStringList(boundResourceID.List())

		body := akeyless.CreateAuthMethodAzureAD{
			Name:               path,
			AccessExpires:      &accessExpires,
			BoundIps:           &boundIpsList,
			BoundTenantId:      boundTenantId,
			BoundSpid:          &boundSpidList,
			BoundGroupId:       &boundGroupIDList,
			BoundSubId:         &boundSubIDList,
			BoundRgId:          &boundRgIDList,
			BoundProviders:     &boundProvidersList,
			BoundResourceTypes: &boundResourceTypesList,
			BoundResourceNames: &boundResourceNamesList,
			BoundResourceId:    &boundResourceIDList,
			JwksUri:            akeyless.PtrString(jwksUri),
			Audience:           akeyless.PtrString(audience),
			Issuer:             akeyless.PtrString(issuer),
			Token:              &token,
		}
		apiKey, _, err := client.CreateAuthMethodAzureAD(ctx).Body(body).Execute()
		if err != nil {
			return err
		}
		err = d.Set("access_id", apiKey.AccessId)
		if err != nil {
			return err
		}
		d.SetId(path)
		return nil
	}

	gcpAuthMethod := d.Get("gcp").([]interface{})
	if gcpAuthMethod != nil && len(gcpAuthMethod) == 1 {
		gcp := gcpAuthMethod[0].(map[string]interface{})
		audience := gcp["audience"].(string)
		serviceAccountCredsData := gcp["service_account_creds_data"].(string)
		body := akeyless.CreateAuthMethodGCP{
			Name:                    path,
			BoundIps:                &boundIpsList,
			AccessExpires:           &accessExpires,
			Audience:                audience,
			ServiceAccountCredsData: akeyless.PtrString(serviceAccountCredsData),
			Token:                   &token,
		}

		iam := gcp["iam"].([]interface{})
		if iam != nil && len(iam) == 1 {
			iamObj, ok := iam[0].(map[string]interface{})
			if ok {
				if iamObj["bound_service_accounts"] != nil {
					boundServiceAccounts := iamObj["bound_service_accounts"].(*schema.Set)
					boundServiceAccountsList := common.ExpandStringList(boundServiceAccounts.List())
					body.BoundServiceAccounts = &boundServiceAccountsList
				}
			}
			body.Type = "iam"
		}

		gce := gcp["gce"].([]interface{})
		if gce != nil && len(gce) == 1 {
			gceObj, ok := gce[0].(map[string]interface{})
			if ok {
				if gceObj["bound_zones"] != nil {
					boundZones := gceObj["bound_zones"].(*schema.Set)
					boundZonesList := common.ExpandStringList(boundZones.List())
					body.BoundZones = &boundZonesList
				}
				if gceObj["bound_regions"] != nil {
					boundRegions := gceObj["bound_regions"].(*schema.Set)
					boundRegionsList := common.ExpandStringList(boundRegions.List())
					body.BoundRegions = &boundRegionsList
				}
				if gceObj["bound_labels"] != nil {
					boundLabels := gceObj["bound_labels"].(*schema.Set)
					boundLabelsList := common.ExpandStringList(boundLabels.List())
					body.BoundLabels = &boundLabelsList
				}
			}
			body.Type = "gce"
		}

		apiKey, _, err := client.CreateAuthMethodGCP(ctx).Body(body).Execute()
		if err != nil {
			return err
		}
		err = d.Set("access_id", apiKey.AccessId)
		if err != nil {
			return err
		}
		d.SetId(path)

		return nil
	}

	return nil
}
