package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceGetTargetDetails() *schema.Resource {
	return &schema.Resource{
		Description: "Get target details data source",
		Read:        dataSourceGetTargetDetailsRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"target_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Target version",
			},
			"show_versions": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Include all target versions in reply",
				Default:     false,
			},
			"value": {
				Type:     schema.TypeMap,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"target_id": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Target ID",
			},
			"target_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Target type",
			},
			"target_sub_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Target sub type",
			},
			"comment": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Comment about the target",
			},
			"protection_key_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Protection key name",
			},
			"last_version": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Last version of the target",
			},
			"with_customer_fragment": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the target has customer fragment",
			},
			"is_access_request_enabled": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether access request is enabled for this target",
			},
			"access_request_status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Access request status",
			},
			"access_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Access date",
			},
			"access_date_display": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Access date display",
			},
			"attributes": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Target attributes",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"client_permissions": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Client permissions",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"creation_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Creation date",
			},
			"modification_date": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Modification date",
			},
			"parent_target_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Parent target name",
			},
			"target_details": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Target details",
			},
			"target_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Target name",
			},
		},
	}
}

func dataSourceGetTargetDetailsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetVersion := d.Get("target_version").(int)
	showVersions := d.Get("show_versions").(bool)

	body := akeyless_api.TargetGetDetails{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetVersion, targetVersion)
	common.GetAkeylessPtr(&body.ShowVersions, showVersions)

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't get target details: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get target details: %v", err)
	}
	if rOut.Value == nil {
		return fmt.Errorf("can't get target details: empty details")
	}

	targetType, err := getTargetType(rOut.Target)
	if err != nil {
		return err
	}

	err = setTargetDetailsByType(d, rOut.Value, targetType)
	if err != nil {
		return err
	}

	if rOut.Target != nil {
		if rOut.Target.TargetId != nil {
			if err := d.Set("target_id", *rOut.Target.TargetId); err != nil {
				return err
			}
		}
		if rOut.Target.TargetType != nil {
			if err := d.Set("target_type", *rOut.Target.TargetType); err != nil {
				return err
			}
		}
		if rOut.Target.TargetSubType != nil {
			if err := d.Set("target_sub_type", *rOut.Target.TargetSubType); err != nil {
				return err
			}
		}
		if rOut.Target.Comment != nil {
			if err := d.Set("comment", *rOut.Target.Comment); err != nil {
				return err
			}
		}
		if rOut.Target.ProtectionKeyName != nil {
			if err := d.Set("protection_key_name", *rOut.Target.ProtectionKeyName); err != nil {
				return err
			}
		}
		if rOut.Target.LastVersion != nil {
			if err := d.Set("last_version", *rOut.Target.LastVersion); err != nil {
				return err
			}
		}
		if rOut.Target.WithCustomerFragment != nil {
			if err := d.Set("with_customer_fragment", *rOut.Target.WithCustomerFragment); err != nil {
				return err
			}
		}
		if rOut.Target.IsAccessRequestEnabled != nil {
			if err := d.Set("is_access_request_enabled", *rOut.Target.IsAccessRequestEnabled); err != nil {
				return err
			}
		}
		if rOut.Target.AccessRequestStatus != nil {
			if err := d.Set("access_request_status", *rOut.Target.AccessRequestStatus); err != nil {
				return err
			}
		}
		if rOut.Target.AccessDate != nil {
			if err := d.Set("access_date", rOut.Target.AccessDate.Format("2006-01-02T15:04:05Z07:00")); err != nil {
				return err
			}
		}
		if rOut.Target.AccessDateDisplay != nil {
			if err := d.Set("access_date_display", *rOut.Target.AccessDateDisplay); err != nil {
				return err
			}
		}
		if rOut.Target.Attributes != nil {
			attributesMap := make(map[string]string)
			for k, v := range rOut.Target.Attributes {
				attributesMap[k] = fmt.Sprintf("%v", v)
			}
			if err := d.Set("attributes", attributesMap); err != nil {
				return err
			}
		}
		if rOut.Target.ClientPermissions != nil {
			if err := d.Set("client_permissions", rOut.Target.ClientPermissions); err != nil {
				return err
			}
		}
		if rOut.Target.CreationDate != nil {
			if err := d.Set("creation_date", rOut.Target.CreationDate.Format("2006-01-02T15:04:05Z07:00")); err != nil {
				return err
			}
		}
		if rOut.Target.ModificationDate != nil {
			if err := d.Set("modification_date", rOut.Target.ModificationDate.Format("2006-01-02T15:04:05Z07:00")); err != nil {
				return err
			}
		}
		if rOut.Target.ParentTargetName != nil {
			if err := d.Set("parent_target_name", *rOut.Target.ParentTargetName); err != nil {
				return err
			}
		}
		if rOut.Target.TargetDetails != nil {
			if err := d.Set("target_details", *rOut.Target.TargetDetails); err != nil {
				return err
			}
		}
		if rOut.Target.TargetName != nil {
			if err := d.Set("target_name", *rOut.Target.TargetName); err != nil {
				return err
			}
		}
	}

	d.SetId(name)
	return nil
}

func getTargetType(targetOut *akeyless_api.Target) (string, error) {

	if targetOut == nil {
		return "", errors.New("empty target")
	}

	targetType := targetOut.TargetType
	if targetType == nil {
		return "", errors.New("unknown target type")
	}
	return *targetType, nil
}

func setTargetDetailsByType(d *schema.ResourceData, details *akeyless_api.TargetTypeDetailsInput, targetType string) error {
	value, err := extractTargetDetailsByType(details, targetType)
	if err != nil {
		return err
	}

	err = d.Set("value", value)
	if err != nil {
		return err
	}
	return nil
}

func extractTargetDetailsByType(details *akeyless_api.TargetTypeDetailsInput, targetType string) (map[string]string, error) {
	switch {
	case details.ArtifactoryTargetDetails != nil:
		return extractArtifactoryTargetDetails(details.ArtifactoryTargetDetails)
	case details.AwsTargetDetails != nil:
		return extractAwsTargetDetails(details.AwsTargetDetails)
	case details.AzureTargetDetails != nil:
		return extractAzureTargetDetails(details.AzureTargetDetails)
	case details.ChefTargetDetails != nil:
		return extractChefTargetDetails(details.ChefTargetDetails)
	case details.CustomTargetDetails != nil:
		return extractCustomTargetDetails(details.CustomTargetDetails)
	case details.DbTargetDetails != nil && targetType != "mongodb":
		return extractDbTargetDetails(details.DbTargetDetails)
	case details.DockerhubTargetDetails != nil:
		return extractDockerhubTargetDetails(details.DockerhubTargetDetails)
	case details.EksTargetDetails != nil:
		return extractEksTargetDetails(details.EksTargetDetails)
	case details.GcpTargetDetails != nil:
		return extractGcpTargetDetails(details.GcpTargetDetails)
	case details.GeminiTargetDetails != nil:
		return extractGeminiTargetDetails(details.GeminiTargetDetails)
	case details.GithubTargetDetails != nil:
		return extractGithubTargetDetails(details.GithubTargetDetails)
	case details.GitlabTargetDetails != nil:
		return extractGitlabTargetDetails(details.GitlabTargetDetails)
	case details.GkeTargetDetails != nil:
		return extractGkeTargetDetails(details.GkeTargetDetails)
	case details.GlobalsignAtlasTargetDetails != nil:
		return extractGlobalsignAtlasTargetDetails(details.GlobalsignAtlasTargetDetails)
	case details.GlobalsignTargetDetails != nil:
		return extractGlobalsignTargetDetails(details.GlobalsignTargetDetails)
	case details.GodaddyTargetDetails != nil:
		return extractGodaddyTargetDetails(details.GodaddyTargetDetails)
	case details.HashiVaultTargetDetails != nil:
		return extractHashiTargetDetails(details.HashiVaultTargetDetails)
	case details.LdapTargetDetails != nil:
		return extractLdapTargetDetails(details.LdapTargetDetails)
	case details.LinkedTargetDetails != nil:
		return extractLinkedTargetDetails(details.LinkedTargetDetails)
	case details.MongoDbTargetDetails != nil:
		return extractMongoDbTargetDetails(details.MongoDbTargetDetails)
	case details.NativeK8sTargetDetails != nil:
		return extractNativeK8sTargetDetails(details.NativeK8sTargetDetails)
	case details.OpenaiTargetDetails != nil:
		return extractOpenaiTargetDetails(details.OpenaiTargetDetails)
	case details.PingTargetDetails != nil:
		return extractPingTargetDetails(details.PingTargetDetails)
	case details.RabbitMqTargetDetails != nil:
		return extractRabbitMqTargetDetails(details.RabbitMqTargetDetails)
	case details.SalesforceTargetDetails != nil:
		return extractSalesforceTargetDetails(details.SalesforceTargetDetails)
	case details.SectigoTargetDetails != nil:
		return extractSectigoTargetDetails(details.SectigoTargetDetails)
	case details.SshTargetDetails != nil:
		return extractSshTargetDetails(details.SshTargetDetails)
	case details.VenafiTargetDetails != nil:
		return extractVenafiTargetDetails(details.VenafiTargetDetails)
	case details.WebTargetDetails != nil:
		return extractWebTargetDetails(details.WebTargetDetails)
	case details.WindowsTargetDetails != nil:
		return extractWindowsTargetDetails(details.WindowsTargetDetails)
	case details.ZerosslTargetDetails != nil:
		return extractZerosslTargetDetails(details.ZerosslTargetDetails)
	default:
		return nil, fmt.Errorf("can't get target details: unknown target type")
	}
}

func extractArtifactoryTargetDetails(details *akeyless_api.ArtifactoryTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.ArtifactoryAdminUsername != nil {
		m["admin_name"] = *details.ArtifactoryAdminUsername
	}
	if details.ArtifactoryAdminApikey != nil {
		m["admin_pwd"] = *details.ArtifactoryAdminApikey
	}
	if details.ArtifactoryBaseUrl != nil {
		m["base_url"] = *details.ArtifactoryBaseUrl
	}

	value, err := buildTargetDetailsVal(m, "artifactory_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractAwsTargetDetails(details *akeyless_api.AWSTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.AwsAccessKeyId != nil {
		m["access_key_id"] = *details.AwsAccessKeyId
	}
	if details.AwsSecretAccessKey != nil {
		m["access_key"] = *details.AwsSecretAccessKey
	}
	if details.AwsSessionToken != nil {
		m["session_token"] = *details.AwsSessionToken
	}
	if details.AwsRegion != nil {
		m["region"] = *details.AwsRegion
	}
	if details.UseGwCloudIdentity != nil {
		m["use_gw_cloud_identity"] = *details.UseGwCloudIdentity
	}

	value, err := buildTargetDetailsVal(m, "aws_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractAzureTargetDetails(details *akeyless_api.AzureTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.AzureClientId != nil {
		m["client_id"] = *details.AzureClientId
	}
	if details.AzureTenantId != nil {
		m["tenant_id"] = *details.AzureTenantId
	}
	if details.AzureClientSecret != nil {
		m["client_secret"] = *details.AzureClientSecret
	}
	if details.AzureSubscriptionId != nil {
		m["subscription_id"] = *details.AzureSubscriptionId
	}
	if details.AzureResourceGroupName != nil {
		m["resource_group_name"] = *details.AzureResourceGroupName
	}
	if details.AzureResourceName != nil {
		m["resource_name"] = *details.AzureResourceName
	}
	if details.UseGwCloudIdentity != nil {
		m["use_gw_cloud_identity"] = *details.UseGwCloudIdentity
	}

	value, err := buildTargetDetailsVal(m, "azure_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractChefTargetDetails(details *akeyless_api.ChefTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.ChefServerUsername != nil {
		m["server_username"] = *details.ChefServerUsername
	}
	if details.ChefServerKey != nil {
		m["server_key"] = *details.ChefServerKey
	}
	if details.ChefServerUrl != nil {
		m["server_url"] = *details.ChefServerUrl
	}
	if details.ChefServerHostName != nil {
		m["server_host_name"] = *details.ChefServerHostName
	}
	if details.ChefServerPort != nil {
		m["server_port"] = *details.ChefServerPort
	}
	if details.ChefSkipSsl != nil {
		m["skip_ssl"] = *details.ChefSkipSsl
	}

	value, err := buildTargetDetailsVal(m, "chef_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractCustomTargetDetails(details *akeyless_api.CustomTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Payload != nil {
		m["custom_payload"] = *details.Payload
	}

	value, err := buildTargetDetailsVal(m, "custom_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractDbTargetDetails(details *akeyless_api.DbTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.DbUserName != nil {
		m["user_name"] = *details.DbUserName
	}
	if details.DbPwd != nil {
		m["pwd"] = *details.DbPwd
	}
	if details.DbHostName != nil {
		m["host"] = *details.DbHostName
	}
	if details.DbPort != nil {
		m["port"] = *details.DbPort
	}
	if details.DbName != nil {
		m["db_name"] = *details.DbName
	}
	if details.SfAccount != nil {
		m["sf_account"] = *details.SfAccount
	}
	if details.DbPrivateKey != nil {
		m["private_key"] = *details.DbPrivateKey
	}
	if details.DbPrivateKeyPassphrase != nil {
		m["private_key_passphrase"] = *details.DbPrivateKeyPassphrase
	}
	if details.DbServerCertificates != nil {
		m["server_certificates"] = *details.DbServerCertificates
	}
	if details.DbServerName != nil {
		m["server_name"] = *details.DbServerName
	}
	if details.SslConnectionMode != nil {
		m["ssl_connection_mode"] = *details.SslConnectionMode
	}
	if details.SslConnectionCertificate != nil {
		m["ssl_connection_certificate"] = *details.SslConnectionCertificate
	}

	value, err := buildTargetDetailsVal(m, "db_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractDockerhubTargetDetails(details *akeyless_api.DockerhubTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.UserName != nil {
		m["username"] = *details.UserName
	}
	if details.Password != nil {
		m["password"] = *details.Password
	}

	value, err := buildTargetDetailsVal(m, "dockerhub_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractEksTargetDetails(details *akeyless_api.EKSTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.EksAccessKeyId != nil {
		m["access_key_id"] = *details.EksAccessKeyId
	}
	if details.EksSecretAccessKey != nil {
		m["access_key"] = *details.EksSecretAccessKey
	}
	if details.EksClusterName != nil {
		m["cluster_name"] = *details.EksClusterName
	}
	if details.EksClusterEndpoint != nil {
		m["cluster_endpoint"] = *details.EksClusterEndpoint
	}
	if details.EksClusterCaCertificate != nil {
		m["cluster_ca_cert"] = *details.EksClusterCaCertificate
	}
	if details.EksRegion != nil {
		m["region"] = *details.EksRegion
	}
	if details.UseGwCloudIdentity != nil {
		m["use_gw_cloud_identity"] = *details.UseGwCloudIdentity
	}

	value, err := buildTargetDetailsVal(m, "eks_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGcpTargetDetails(details *akeyless_api.GcpTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.GcpServiceAccountKey != nil {
		m["gcp_service_account_key"] = *details.GcpServiceAccountKey
	}
	if details.GcpServiceAccountKeyBase64 != nil {
		m["gcp_service_account_key_base64"] = *details.GcpServiceAccountKeyBase64
	}
	if details.UseGwCloudIdentity != nil {
		m["use_gw_cloud_identity"] = *details.UseGwCloudIdentity
	}

	value, err := buildTargetDetailsVal(m, "gcp_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGithubTargetDetails(details *akeyless_api.GithubTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.GithubAppId != nil {
		m["app_id"] = *details.GithubAppId
	}
	if details.GithubAppPrivateKey != nil {
		m["app_private_key"] = *details.GithubAppPrivateKey
	}
	if details.GithubBaseUrl != nil {
		m["base_url"] = *details.GithubBaseUrl
	}

	value, err := buildTargetDetailsVal(m, "github_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGkeTargetDetails(details *akeyless_api.GKETargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.GkeClusterName != nil {
		m["cluster_name"] = *details.GkeClusterName
	}
	if details.GkeClusterEndpoint != nil {
		m["cluster_endpoint"] = *details.GkeClusterEndpoint
	}
	if details.GkeClusterCaCertificate != nil {
		m["cluster_ca_cert"] = *details.GkeClusterCaCertificate
	}
	if details.GkeServiceAccountName != nil {
		m["service_account_email"] = *details.GkeServiceAccountName
	}
	if details.GkeServiceAccountKey != nil {
		m["service_account_key"] = *details.GkeServiceAccountKey
	}
	if details.UseGwCloudIdentity != nil {
		m["use_gw_cloud_identity"] = *details.UseGwCloudIdentity
	}

	value, err := buildTargetDetailsVal(m, "gke_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGlobalsignAtlasTargetDetails(details *akeyless_api.GlobalSignAtlasTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.ApiKey != nil {
		m["api_key"] = *details.ApiKey
	}
	if details.ApiSecret != nil {
		m["api_secret"] = *details.ApiSecret
	}
	if details.MtlsCert != nil {
		m["mutual_tls_cert"] = *details.MtlsCert
	}
	if details.MtlsKey != nil {
		m["mutual_tls_key"] = *details.MtlsKey
	}
	if details.Timeout != nil {
		m["timeout"] = *details.Timeout
	}

	value, err := buildTargetDetailsVal(m, "globalsign_atlas_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGlobalsignTargetDetails(details *akeyless_api.GlobalSignGCCTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Username != nil {
		m["username"] = *details.Username
	}
	if details.Password != nil {
		m["password"] = *details.Password
	}
	if details.ProfileId != nil {
		m["profile_id"] = *details.ProfileId
	}
	if details.FirstName != nil {
		m["contact_first_name"] = *details.FirstName
	}
	if details.LastName != nil {
		m["contact_last_name"] = *details.LastName
	}
	if details.Phone != nil {
		m["contact_phone"] = *details.Phone
	}
	if details.Email != nil {
		m["contact_email"] = *details.Email
	}
	if details.Timeout != nil {
		m["timeout"] = *details.Timeout
	}

	value, err := buildTargetDetailsVal(m, "globalsign_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractHashiTargetDetails(details *akeyless_api.HashiVaultTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.VaultUrl != nil {
		m["vault_url"] = *details.VaultUrl
	}
	if details.VaultToken != nil {
		m["vault_token"] = *details.VaultToken
	}
	if details.VaultNamespaces != nil {
		m["vault_namespaces"] = *details.VaultNamespaces
	}

	value, err := buildTargetDetailsVal(m, "hashi_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractLdapTargetDetails(details *akeyless_api.LdapTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.LdapUrl != nil {
		m["url"] = *details.LdapUrl
	}
	if details.LdapBindDn != nil {
		m["bind_dn"] = *details.LdapBindDn
	}
	if details.LdapBindPassword != nil {
		m["bind_password"] = *details.LdapBindPassword
	}
	if details.LdapTokenExpiration != nil {
		m["token_expiration_in_sec"] = *details.LdapTokenExpiration
	}
	if details.LdapAudience != nil {
		m["audience"] = *details.LdapAudience
	}
	if details.LdapCertificate != nil {
		m["certificate"] = *details.LdapCertificate
	}
	if details.ImplementationType != nil {
		m["implementation_type"] = *details.ImplementationType
	}

	value, err := buildTargetDetailsVal(m, "ldap_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractLinkedTargetDetails(details *akeyless_api.LinkedTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Hosts != nil {
		m["hosts"] = fmt.Sprintf("%v", *details.Hosts)
	}

	value, err := buildTargetDetailsVal(m, "linked_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractMongoDbTargetDetails(details *akeyless_api.MongoDBTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.MongodbDbName != nil {
		m["db_name"] = *details.MongodbDbName
	}
	if details.MongodbUriConnection != nil {
		m["uri_connection"] = *details.MongodbUriConnection
	}
	if details.MongodbUsername != nil {
		m["username"] = *details.MongodbUsername
	}
	if details.MongodbPassword != nil {
		m["password"] = *details.MongodbPassword
	}
	if details.MongodbHostPort != nil {
		m["host_port"] = *details.MongodbHostPort
	}
	if details.MongodbDefaultAuthDb != nil {
		m["default_auth_db"] = *details.MongodbDefaultAuthDb
	}
	if details.MongodbUriOptions != nil {
		m["uri_options"] = *details.MongodbUriOptions
	}
	if details.MongodbAtlasProjectId != nil {
		m["atlas_project_id"] = *details.MongodbAtlasProjectId
	}
	if details.MongodbAtlasApiPublicKey != nil {
		m["atlas_api_public_key"] = *details.MongodbAtlasApiPublicKey
	}
	if details.MongodbAtlasApiPrivateKey != nil {
		m["atlas_api_private_key"] = *details.MongodbAtlasApiPrivateKey
	}
	if details.MongodbIsAtlas != nil {
		m["is_atlas"] = *details.MongodbIsAtlas
	}

	value, err := buildTargetDetailsVal(m, "mongo_db_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractNativeK8sTargetDetails(details *akeyless_api.NativeK8sTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.K8sClusterEndpoint != nil {
		m["cluster_endpoint"] = *details.K8sClusterEndpoint
	}
	if details.K8sClusterCaCertificate != nil {
		m["cluster_ca_cert"] = *details.K8sClusterCaCertificate
	}
	if details.K8sBearerToken != nil {
		m["bearer_token"] = *details.K8sBearerToken
	}
	if details.UseGwServiceAccount != nil {
		m["use_gw_cloud_identity"] = *details.UseGwServiceAccount
	}

	value, err := buildTargetDetailsVal(m, "native_k8s_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractPingTargetDetails(details *akeyless_api.PingTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.PingUrl != nil {
		m["url"] = *details.PingUrl
	}
	if details.PrivilegedUser != nil {
		m["privileged_user"] = *details.PrivilegedUser
	}
	if details.UserPassword != nil {
		m["user_password"] = *details.UserPassword
	}
	if details.AdministrativePort != nil {
		m["administrative_port"] = *details.AdministrativePort
	}
	if details.AuthorizationPort != nil {
		m["authorization_port"] = *details.AuthorizationPort
	}

	value, err := buildTargetDetailsVal(m, "ping_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractRabbitMqTargetDetails(details *akeyless_api.RabbitMQTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.RabbitmqServerUser != nil {
		m["server_user"] = *details.RabbitmqServerUser
	}
	if details.RabbitmqServerPassword != nil {
		m["server_password"] = *details.RabbitmqServerPassword
	}
	if details.RabbitmqServerUri != nil {
		m["server_uri"] = *details.RabbitmqServerUri
	}

	value, err := buildTargetDetailsVal(m, "rabbit_mq_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractSalesforceTargetDetails(details *akeyless_api.SalesforceTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.AuthFlow != nil {
		m["auth_flow"] = *details.AuthFlow
	}
	if details.UserName != nil {
		m["username"] = *details.UserName
	}
	if details.Password != nil {
		m["password"] = *details.Password
	}
	if details.TenantUrl != nil {
		m["tenant_url"] = *details.TenantUrl
	}
	if details.ClientId != nil {
		m["client_id"] = *details.ClientId
	}
	if details.ClientSecret != nil {
		m["client_secret"] = *details.ClientSecret
	}
	if details.SecurityToken != nil {
		m["security_token"] = *details.SecurityToken
	}
	if details.CaCertName != nil {
		m["ca_cert_name"] = *details.CaCertName
	}
	// if details.AppPrivateKey != nil {
	// 	m["app_private_key"] = *details.AppPrivateKey
	// }
	// if details.CaCertData != nil {
	// 	m["ca_cert_data"] = *details.CaCertData
	// }

	value, err := buildTargetDetailsVal(m, "salesforce_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractSshTargetDetails(details *akeyless_api.SSHTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Username != nil {
		m["username"] = *details.Username
	}
	if details.Password != nil {
		m["password"] = *details.Password
	}
	if details.Host != nil {
		m["host"] = *details.Host
	}
	if details.Port != nil {
		m["port"] = *details.Port
	}
	if details.PrivateKey != nil {
		m["private_key"] = *details.PrivateKey
	}
	if details.PrivateKeyPassword != nil {
		m["private_key_password"] = *details.PrivateKeyPassword
	}

	value, err := buildTargetDetailsVal(m, "ssh_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractVenafiTargetDetails(details *akeyless_api.VenafiTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.VenafiApiKey != nil {
		m["api_key"] = *details.VenafiApiKey
	}
	if details.VenafiZone != nil {
		m["zone"] = *details.VenafiZone
	}
	if details.VenafiBaseUrl != nil {
		m["base_url"] = *details.VenafiBaseUrl
	}
	if details.VenafiTppAccessToken != nil {
		m["tpp_access_token"] = *details.VenafiTppAccessToken
	}
	if details.VenafiTppRefreshToken != nil {
		m["tpp_refresh_token"] = *details.VenafiTppRefreshToken
	}
	if details.VenafiTppClientId != nil {
		m["tpp_client_id"] = *details.VenafiTppClientId
	}
	if details.VenafiUseTpp != nil {
		m["use_tpp"] = *details.VenafiUseTpp
	}

	value, err := buildTargetDetailsVal(m, "venafi_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractWebTargetDetails(details *akeyless_api.WebTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Url != nil {
		m["url"] = *details.Url
	}

	value, err := buildTargetDetailsVal(m, "web_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractWindowsTargetDetails(details *akeyless_api.WindowsTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Username != nil {
		m["username"] = *details.Username
	}
	if details.Password != nil {
		m["password"] = *details.Password
	}
	if details.Hostname != nil {
		m["hostname"] = *details.Hostname
	}
	if details.Port != nil {
		m["port"] = *details.Port
	}
	if details.DomainName != nil {
		m["domain"] = *details.DomainName
	}
	if details.Certificate != nil {
		m["certificate"] = *details.Certificate
	}
	if details.UseTls != nil {
		m["use_tls"] = *details.UseTls
	}

	value, err := buildTargetDetailsVal(m, "windows_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractZerosslTargetDetails(details *akeyless_api.ZeroSSLTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.ApiKey != nil {
		m["api_key"] = *details.ApiKey
	}
	if details.ImapUser != nil {
		m["imap_username"] = *details.ImapUser
	}
	if details.ImapPassword != nil {
		m["imap_password"] = *details.ImapPassword
	}
	if details.ImapFqdn != nil {
		m["imap_fqdn"] = *details.ImapFqdn
	}
	if details.ImapPort != nil {
		m["imap_port"] = *details.ImapPort
	}
	if details.ValidationEmail != nil {
		m["validation_email"] = *details.ValidationEmail
	}
	if details.Timeout != nil {
		m["timeout"] = *details.Timeout
	}

	value, err := buildTargetDetailsVal(m, "zerossl_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGeminiTargetDetails(details *akeyless_api.GeminiTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.ApiKey != nil {
		m["api_key"] = *details.ApiKey
	}
	if details.GeminiUrl != nil {
		m["gemini_url"] = *details.GeminiUrl
	}

	value, err := buildTargetDetailsVal(m, "gemini_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractOpenaiTargetDetails(details *akeyless_api.OpenAITargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.ApiKey != nil {
		m["api_key"] = *details.ApiKey
	}
	if details.ApiKeyId != nil {
		m["api_key_id"] = *details.ApiKeyId
	}
	if details.OpenaiUrl != nil {
		m["openai_url"] = *details.OpenaiUrl
	}
	if details.OrganizationId != nil {
		m["organization_id"] = *details.OrganizationId
	}
	if details.ProjectId != nil {
		m["project_id"] = *details.ProjectId
	}

	value, err := buildTargetDetailsVal(m, "openai_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGodaddyTargetDetails(details *akeyless_api.GodaddyTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Key != nil {
		m["key"] = *details.Key
	}
	if details.Secret != nil {
		m["secret"] = *details.Secret
	}
	if details.ImapUser != nil {
		m["imap_username"] = *details.ImapUser
	}
	if details.ImapPassword != nil {
		m["imap_password"] = *details.ImapPassword
	}
	if details.ImapFqdn != nil {
		m["imap_fqdn"] = *details.ImapFqdn
	}
	if details.ImapPort != nil {
		m["imap_port"] = *details.ImapPort
	}
	if details.ValidationEmail != nil {
		m["validation_email"] = *details.ValidationEmail
	}
	if details.ShopperId != nil {
		m["shopper_id"] = *details.ShopperId
	}
	if details.Timeout != nil {
		m["timeout"] = *details.Timeout
	}

	value, err := buildTargetDetailsVal(m, "godaddy_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractGitlabTargetDetails(details *akeyless_api.GitlabTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.GitlabAccessToken != nil {
		m["access_token"] = *details.GitlabAccessToken
	}
	if details.GitlabCertificate != nil {
		m["certificate"] = *details.GitlabCertificate
	}
	if details.GitlabUrl != nil {
		m["url"] = *details.GitlabUrl
	}

	value, err := buildTargetDetailsVal(m, "gitlab_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func extractSectigoTargetDetails(details *akeyless_api.SectigoTargetDetails) (map[string]string, error) {

	m := make(map[string]interface{})

	if details.Username != nil {
		m["username"] = *details.Username
	}
	if details.Password != nil {
		m["password"] = *details.Password
	}
	if details.CustomerUri != nil {
		m["customer_uri"] = *details.CustomerUri
	}
	if details.OrgId != nil {
		m["org_id"] = *details.OrgId
	}
	if details.CertificateProfileId != nil {
		m["certificate_profile_id"] = *details.CertificateProfileId
	}
	if details.ExternalRequester != nil {
		m["external_requester"] = *details.ExternalRequester
	}
	if details.Timeout != nil {
		m["timeout"] = *details.Timeout
	}

	value, err := buildTargetDetailsVal(m, "sectigo_target_details")
	if err != nil {
		return nil, err
	}
	return value, nil
}

func buildTargetDetailsVal(m map[string]interface{}, targetType string) (map[string]string, error) {

	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	return map[string]string{targetType: string(b)}, nil
}
