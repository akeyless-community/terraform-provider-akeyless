package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v3"
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
				Default:     "false",
			},
			"artifactory_admin_apikey": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"artifactory_admin_username": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"artifactory_base_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"aws_access_key_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"aws_secret_access_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"aws_session_token": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"aws_region": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"azure_client_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"azure_tenant_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"azure_client_secret": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"azure_subscription_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"azure_resource_group_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"azure_resource_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"chef_server_username": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"chef_server_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"chef_server_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"chef_server_host_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"chef_server_port": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"chef_skip_ssl": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"custom_payload": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"db_user_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"db_pwd": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"db_host_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"db_port": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"db_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"sf_account": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"db_private_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"db_private_key_passphrase": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"db_server_certificates": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"db_server_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"db_ssl_connection_mode": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"db_ssl_connection_certificate": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"dockerhub_user_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"dockerhub_password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"eks_access_key_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"eks_secret_access_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"eks_region": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"eks_cluster_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"eks_cluster_endpoint": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"eks_cluster_ca_certificate": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"gcp_service_account_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"gcp_service_account_key_base64": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"github_app_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"github_app_private_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"github_base_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"gke_cluster_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"gke_cluster_endpoint": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"gke_cluster_ca_certificate": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"gke_service_account_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"gke_service_account_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"global_sign_atlas_api_key": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"global_sign_atlas_api_secret": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"global_sign_atlas_mutual_tls_cert": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"global_sign_atlas_mutual_tls_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"global_sign_username": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"global_sign_password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"global_sign_profile_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"global_sign_first_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"global_sign_last_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"global_sign_phone": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"global_sign_email": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ldap_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ldap_bind_dn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ldap_bind_password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"ldap_token_expiration_in_sec": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ldap_audience": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ldap_certificate": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"ldap_implementation_type": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"linked_target_hosts": {
				Type:     schema.TypeMap,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"mongodb_db_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"mongodb_uri_connection": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"mongodb_username": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"mongodb_password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"mongodb_host_port": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"mongodb_default_auth_db": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"mongodb_uri_options": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"mongodb_atlas_project_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"mongodb_atlas_api_public_key": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"mongodb_atlas_api_private_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"mongodb_is_atlas": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"k8s_cluster_endpoint": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"k8s_cluster_ca_certificate": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"k8s_bearer_token": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"ping_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ping_privileged_user": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ping_user_password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"ping_administrative_port": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ping_authorization_port": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"rabbitmq_server_user": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"rabbitmq_server_password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"rabbitmq_server_uri": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"salesforce_auth_flow": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"salesforce_user_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"salesforce_password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"salesforce_tenant_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"salesforce_client_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"salesforce_client_secret": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"salesforce_security_token": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"salesforce_ca_cert_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ssh_username": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ssh_password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"ssh_host": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ssh_port": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ssh_private_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"ssh_private_key_password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"venafi_api_key": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"venafi_zone": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"venafi_base_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"venafi_tpp_access_token": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"venafi_tpp_refresh_token": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"venafi_tpp_client_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"venafi_use_tpp": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"web_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"windows_username": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"windows_password": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"windows_hostname": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"windows_port": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"windows_domain_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"windows_certificate": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"windows_use_tls": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"zerossl_api_key": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"zerossl_imap_user": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"zerossl_imap_password": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"zerossl_imap_fqdn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"zerossl_validation_email": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"zerossl_imap_port": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"timeout": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"use_gw_cloud_identity": {
				Type:     schema.TypeBool,
				Computed: true,
			},
		},
	}
}

func dataSourceGetTargetDetailsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetVersion := d.Get("target_version").(int)
	showVersions := d.Get("show_versions").(bool)

	body := akeyless.GetTargetDetails{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetVersion, targetVersion)
	common.GetAkeylessPtr(&body.ShowVersions, showVersions)

	rOut, res, err := client.GetTargetDetails(ctx).Body(body).Execute()
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

	err = setTargetDetailsByType(d, rOut.Value)
	if err != nil {
		return err
	}

	d.SetId(name)
	return nil
}

func setTargetDetailsByType(d *schema.ResourceData, value *akeyless.TargetTypeDetailsInput) error {
	switch {
	case value.ArtifactoryTargetDetails != nil:
		return setArtifactoryTargetDetails(d, value.ArtifactoryTargetDetails)
	case value.AwsTargetDetails != nil:
		return setAwsTargetDetails(d, value.AwsTargetDetails)
	case value.AzureTargetDetails != nil:
		return setAzureTargetDetails(d, value.AzureTargetDetails)
	case value.ChefTargetDetails != nil:
		return setChefTargetDetails(d, value.ChefTargetDetails)
	case value.CustomTargetDetails != nil:
		return setCustomTargetDetails(d, value.CustomTargetDetails)
	case value.DbTargetDetails != nil:
		return setDbTargetDetails(d, value.DbTargetDetails)
	case value.DockerhubTargetDetails != nil:
		return setDockerhubTargetDetails(d, value.DockerhubTargetDetails)
	case value.EksTargetDetails != nil:
		return setEksTargetDetails(d, value.EksTargetDetails)
	case value.GcpTargetDetails != nil:
		return setGcpTargetDetails(d, value.GcpTargetDetails)
	case value.GithubTargetDetails != nil:
		return setGithubTargetDetails(d, value.GithubTargetDetails)
	case value.GkeTargetDetails != nil:
		return setGkeTargetDetails(d, value.GkeTargetDetails)
	case value.GlobalsignAtlasTargetDetails != nil:
		return setGlobalsignAtlasTargetDetails(d, value.GlobalsignAtlasTargetDetails)
	case value.GlobalsignTargetDetails != nil:
		return setGlobalsignTargetDetails(d, value.GlobalsignTargetDetails)
	case value.LdapTargetDetails != nil:
		return setLdapTargetDetails(d, value.LdapTargetDetails)
	case value.LinkedTargetDetails != nil:
		return setLinkedTargetDetails(d, value.LinkedTargetDetails)
	case value.MongoDbTargetDetails != nil:
		return setMongoDbTargetDetails(d, value.MongoDbTargetDetails)
	case value.NativeK8sTargetDetails != nil:
		return setNativeK8sTargetDetails(d, value.NativeK8sTargetDetails)
	case value.PingTargetDetails != nil:
		return setPingTargetDetails(d, value.PingTargetDetails)
	case value.RabbitMqTargetDetails != nil:
		return setRabbitMqTargetDetails(d, value.RabbitMqTargetDetails)
	case value.SalesforceTargetDetails != nil:
		return setSalesforceTargetDetails(d, value.SalesforceTargetDetails)
	case value.SshTargetDetails != nil:
		return setSshTargetDetails(d, value.SshTargetDetails)
	case value.VenafiTargetDetails != nil:
		return setVenafiTargetDetails(d, value.VenafiTargetDetails)
	case value.WebTargetDetails != nil:
		return setWebTargetDetails(d, value.WebTargetDetails)
	case value.WindowsTargetDetails != nil:
		return setWindowsTargetDetails(d, value.WindowsTargetDetails)
	case value.ZerosslTargetDetails != nil:
		return setZerosslTargetDetails(d, value.ZerosslTargetDetails)
	default:
		return fmt.Errorf("can't get target details: unknown target details type")
	}
}

func setArtifactoryTargetDetails(d *schema.ResourceData, details *akeyless.ArtifactoryTargetDetails) error {
	if details.ArtifactoryAdminApikey != nil {
		err := d.Set("artifactory_admin_apikey", *details.ArtifactoryAdminApikey)
		if err != nil {
			return err
		}
	}
	if details.ArtifactoryAdminUsername != nil {
		err := d.Set("artifactory_admin_username", *details.ArtifactoryAdminUsername)
		if err != nil {
			return err
		}
	}
	if details.ArtifactoryBaseUrl != nil {
		err := d.Set("artifactory_base_url", *details.ArtifactoryBaseUrl)
		if err != nil {
			return err
		}
	}

	return nil
}

func setAwsTargetDetails(d *schema.ResourceData, details *akeyless.AWSTargetDetails) error {
	if details.AwsAccessKeyId != nil {
		err := d.Set("aws_access_key_id", *details.AwsAccessKeyId)
		if err != nil {
			return err
		}
	}
	if details.AwsSecretAccessKey != nil {
		err := d.Set("aws_secret_access_key", *details.AwsSecretAccessKey)
		if err != nil {
			return err
		}
	}
	if details.AwsSessionToken != nil {
		err := d.Set("aws_session_token", *details.AwsSessionToken)
		if err != nil {
			return err
		}
	}
	if details.AwsRegion != nil {
		err := d.Set("aws_region", *details.AwsRegion)
		if err != nil {
			return err
		}
	}
	if details.UseGwCloudIdentity != nil {
		err := d.Set("use_gw_cloud_identity", *details.UseGwCloudIdentity)
		if err != nil {
			return err
		}
	}

	return nil
}

func setAzureTargetDetails(d *schema.ResourceData, details *akeyless.AzureTargetDetails) error {
	if details.AzureClientId != nil {
		err := d.Set("azure_client_id", *details.AzureClientId)
		if err != nil {
			return err
		}
	}
	if details.AzureTenantId != nil {
		err := d.Set("azure_tenant_id", *details.AzureTenantId)
		if err != nil {
			return err
		}
	}
	if details.AzureClientSecret != nil {
		err := d.Set("azure_client_secret", *details.AzureClientSecret)
		if err != nil {
			return err
		}
	}
	if details.AzureSubscriptionId != nil {
		err := d.Set("azure_subscription_id", *details.AzureSubscriptionId)
		if err != nil {
			return err
		}
	}
	if details.AzureResourceGroupName != nil {
		err := d.Set("azure_resource_group_name", *details.AzureResourceGroupName)
		if err != nil {
			return err
		}
	}
	if details.AzureResourceName != nil {
		err := d.Set("azure_resource_name", *details.AzureResourceName)
		if err != nil {
			return err
		}
	}
	if details.UseGwCloudIdentity != nil {
		err := d.Set("use_gw_cloud_identity", *details.UseGwCloudIdentity)
		if err != nil {
			return err
		}
	}

	return nil
}

func setChefTargetDetails(d *schema.ResourceData, details *akeyless.ChefTargetDetails) error {
	if details.ChefServerUsername != nil {
		err := d.Set("chef_server_username", *details.ChefServerUsername)
		if err != nil {
			return err
		}
	}
	if details.ChefServerKey != nil {
		err := d.Set("chef_server_key", *details.ChefServerKey)
		if err != nil {
			return err
		}
	}
	if details.ChefServerUrl != nil {
		err := d.Set("chef_server_url", *details.ChefServerUrl)
		if err != nil {
			return err
		}
	}
	if details.ChefServerHostName != nil {
		err := d.Set("chef_server_host_name", *details.ChefServerHostName)
		if err != nil {
			return err
		}
	}
	if details.ChefServerPort != nil {
		err := d.Set("chef_server_port", *details.ChefServerPort)
		if err != nil {
			return err
		}
	}
	if details.ChefSkipSsl != nil {
		err := d.Set("chef_skip_ssl", *details.ChefSkipSsl)
		if err != nil {
			return err
		}
	}

	return nil
}

func setCustomTargetDetails(d *schema.ResourceData, details *akeyless.CustomTargetDetails) error {
	if details.Payload != nil {
		err := d.Set("custom_payload", *details.Payload)
		if err != nil {
			return err
		}
	}

	return nil
}

func setDbTargetDetails(d *schema.ResourceData, details *akeyless.DbTargetDetails) error {
	if details.DbUserName != nil {
		err := d.Set("db_user_name", *details.DbUserName)
		if err != nil {
			return err
		}
	}
	if details.DbPwd != nil {
		err := d.Set("db_pwd", *details.DbPwd)
		if err != nil {
			return err
		}
	}
	if details.DbHostName != nil {
		err := d.Set("db_host_name", *details.DbHostName)
		if err != nil {
			return err
		}
	}
	if details.DbPort != nil {
		err := d.Set("db_port", *details.DbPort)
		if err != nil {
			return err
		}
	}
	if details.DbName != nil {
		err := d.Set("db_name", *details.DbName)
		if err != nil {
			return err
		}
	}
	if details.SfAccount != nil {
		err := d.Set("sf_account", *details.SfAccount)
		if err != nil {
			return err
		}
	}
	if details.DbPrivateKey != nil {
		err := d.Set("db_private_key", *details.DbPrivateKey)
		if err != nil {
			return err
		}
	}
	if details.DbPrivateKeyPassphrase != nil {
		err := d.Set("db_private_key_passphrase", *details.DbPrivateKeyPassphrase)
		if err != nil {
			return err
		}
	}
	if details.DbServerCertificates != nil {
		err := d.Set("db_server_certificates", *details.DbServerCertificates)
		if err != nil {
			return err
		}
	}
	if details.DbServerName != nil {
		err := d.Set("db_server_name", *details.DbServerName)
		if err != nil {
			return err
		}
	}
	if details.SslConnectionMode != nil {
		err := d.Set("db_ssl_connection_mode", *details.SslConnectionMode)
		if err != nil {
			return err
		}
	}
	if details.SslConnectionCertificate != nil {
		err := d.Set("db_ssl_connection_certificate", *details.SslConnectionCertificate)
		if err != nil {
			return err
		}
	}

	return nil
}

func setDockerhubTargetDetails(d *schema.ResourceData, details *akeyless.DockerhubTargetDetails) error {
	if details.UserName != nil {
		err := d.Set("dockerhub_user_name", *details.UserName)
		if err != nil {
			return err
		}
	}
	if details.Password != nil {
		err := d.Set("dockerhub_password", *details.Password)
		if err != nil {
			return err
		}
	}

	return nil
}

func setEksTargetDetails(d *schema.ResourceData, details *akeyless.EKSTargetDetails) error {
	if details.EksAccessKeyId != nil {
		err := d.Set("eks_access_key_id", *details.EksAccessKeyId)
		if err != nil {
			return err
		}
	}
	if details.EksSecretAccessKey != nil {
		err := d.Set("eks_secret_access_key", *details.EksSecretAccessKey)
		if err != nil {
			return err
		}
	}
	if details.EksRegion != nil {
		err := d.Set("eks_region", *details.EksRegion)
		if err != nil {
			return err
		}
	}
	if details.EksClusterName != nil {
		err := d.Set("eks_cluster_name", *details.EksClusterName)
		if err != nil {
			return err
		}
	}
	if details.EksClusterEndpoint != nil {
		err := d.Set("eks_cluster_endpoint", *details.EksClusterEndpoint)
		if err != nil {
			return err
		}
	}
	if details.EksClusterCaCertificate != nil {
		err := d.Set("eks_cluster_ca_certificate", *details.EksClusterCaCertificate)
		if err != nil {
			return err
		}
	}
	if details.UseGwCloudIdentity != nil {
		err := d.Set("use_gw_cloud_identity", *details.UseGwCloudIdentity)
		if err != nil {
			return err
		}
	}

	return nil
}

func setGcpTargetDetails(d *schema.ResourceData, details *akeyless.GcpTargetDetails) error {
	if details.GcpServiceAccountKey != nil {
		err := d.Set("gcp_service_account_key", *details.GcpServiceAccountKey)
		if err != nil {
			return err
		}
	}
	if details.GcpServiceAccountKeyBase64 != nil {
		err := d.Set("gcp_service_account_key_base64", *details.GcpServiceAccountKeyBase64)
		if err != nil {
			return err
		}
	}
	if details.UseGwCloudIdentity != nil {
		err := d.Set("use_gw_cloud_identity", *details.UseGwCloudIdentity)
		if err != nil {
			return err
		}
	}

	return nil
}

func setGithubTargetDetails(d *schema.ResourceData, details *akeyless.GithubTargetDetails) error {
	if details.GithubAppId != nil {
		err := d.Set("github_app_id", *details.GithubAppId) // int64
		if err != nil {
			return err
		}
	}
	if details.GithubAppPrivateKey != nil {
		err := d.Set("github_app_private_key", *details.GithubAppPrivateKey)
		if err != nil {
			return err
		}
	}
	if details.GithubBaseUrl != nil {
		err := d.Set("github_base_url", *details.GithubBaseUrl)
		if err != nil {
			return err
		}
	}

	return nil
}

func setGkeTargetDetails(d *schema.ResourceData, details *akeyless.GKETargetDetails) error {
	if details.GkeClusterName != nil {
		err := d.Set("gke_cluster_name", *details.GkeClusterName)
		if err != nil {
			return err
		}
	}
	if details.GkeClusterEndpoint != nil {
		err := d.Set("gke_cluster_endpoint", *details.GkeClusterEndpoint)
		if err != nil {
			return err
		}
	}
	if details.GkeClusterCaCertificate != nil {
		err := d.Set("gke_cluster_ca_certificate", *details.GkeClusterCaCertificate)
		if err != nil {
			return err
		}
	}
	if details.GkeServiceAccountName != nil {
		err := d.Set("gke_service_account_name", *details.GkeServiceAccountName)
		if err != nil {
			return err
		}
	}
	if details.GkeServiceAccountKey != nil {
		err := d.Set("gke_service_account_key", *details.GkeServiceAccountKey)
		if err != nil {
			return err
		}
	}
	if details.UseGwCloudIdentity != nil {
		err := d.Set("use_gw_cloud_identity", *details.UseGwCloudIdentity)
		if err != nil {
			return err
		}
	}

	return nil
}

func setGlobalsignAtlasTargetDetails(d *schema.ResourceData, details *akeyless.GlobalSignAtlasTargetDetails) error {
	if details.ApiKey != nil {
		err := d.Set("global_sign_atlas_api_key", *details.ApiKey)
		if err != nil {
			return err
		}
	}
	if details.ApiSecret != nil {
		err := d.Set("global_sign_atlas_api_secret", *details.ApiSecret)
		if err != nil {
			return err
		}
	}
	if details.MtlsCert != nil {
		err := d.Set("global_sign_atlas_mutual_tls_cert", *details.MtlsCert)
		if err != nil {
			return err
		}
	}
	if details.MtlsKey != nil {
		err := d.Set("global_sign_atlas_mutual_tls_key", *details.MtlsKey)
		if err != nil {
			return err
		}
	}
	if details.Timeout != nil {
		err := d.Set("timeout", *details.Timeout)
		if err != nil {
			return err
		}
	}

	return nil
}

func setGlobalsignTargetDetails(d *schema.ResourceData, details *akeyless.GlobalSignGCCTargetDetails) error {
	if details.Username != nil {
		err := d.Set("global_sign_username", *details.Username)
		if err != nil {
			return err
		}
	}
	if details.Password != nil {
		err := d.Set("global_sign_password", *details.Password)
		if err != nil {
			return err
		}
	}
	if details.ProfileId != nil {
		err := d.Set("global_sign_profile_id", *details.ProfileId)
		if err != nil {
			return err
		}
	}
	if details.FirstName != nil {
		err := d.Set("global_sign_first_name", *details.FirstName)
		if err != nil {
			return err
		}
	}
	if details.LastName != nil {
		err := d.Set("global_sign_last_name", *details.LastName)
		if err != nil {
			return err
		}
	}
	if details.Phone != nil {
		err := d.Set("global_sign_phone", *details.Phone)
		if err != nil {
			return err
		}
	}
	if details.Email != nil {
		err := d.Set("global_sign_email", *details.Email)
		if err != nil {
			return err
		}
	}
	if details.Timeout != nil {
		err := d.Set("timeout", *details.Timeout)
		if err != nil {
			return err
		}
	}

	return nil
}

func setLdapTargetDetails(d *schema.ResourceData, details *akeyless.LdapTargetDetails) error {
	if details.LdapUrl != nil {
		err := d.Set("ldap_url", *details.LdapUrl)
		if err != nil {
			return err
		}
	}
	if details.LdapBindDn != nil {
		err := d.Set("ldap_bind_dn", *details.LdapBindDn)
		if err != nil {
			return err
		}
	}
	if details.LdapBindPassword != nil {
		err := d.Set("ldap_bind_password", *details.LdapBindPassword)
		if err != nil {
			return err
		}
	}
	if details.LdapTokenExpiration != nil {
		err := d.Set("ldap_token_expiration_in_sec", *details.LdapTokenExpiration)
		if err != nil {
			return err
		}
	}
	if details.LdapAudience != nil {
		err := d.Set("ldap_audience", *details.LdapAudience)
		if err != nil {
			return err
		}
	}
	if details.LdapCertificate != nil {
		err := d.Set("ldap_certificate", *details.LdapCertificate)
		if err != nil {
			return err
		}
	}
	if details.ImplementationType != nil {
		err := d.Set("ldap_implementation_type", *details.ImplementationType)
		if err != nil {
			return err
		}
	}

	return nil
}

func setLinkedTargetDetails(d *schema.ResourceData, details *akeyless.LinkedTargetDetails) error {
	if details.Hosts != nil {
		err := d.Set("linked_target_hosts", *details.Hosts)
		if err != nil {
			return err
		}
	}

	return nil
}

func setMongoDbTargetDetails(d *schema.ResourceData, details *akeyless.MongoDBTargetDetails) error {
	if details.MongodbDbName != nil {
		err := d.Set("mongodb_db_name", *details.MongodbDbName)
		if err != nil {
			return err
		}
	}
	if details.MongodbUriConnection != nil {
		err := d.Set("mongodb_uri_connection", *details.MongodbUriConnection)
		if err != nil {
			return err
		}
	}
	if details.MongodbUsername != nil {
		err := d.Set("mongodb_username", *details.MongodbUsername)
		if err != nil {
			return err
		}
	}
	if details.MongodbPassword != nil {
		err := d.Set("mongodb_password", *details.MongodbPassword)
		if err != nil {
			return err
		}
	}
	if details.MongodbHostPort != nil {
		err := d.Set("mongodb_host_port", *details.MongodbHostPort)
		if err != nil {
			return err
		}
	}
	if details.MongodbDefaultAuthDb != nil {
		err := d.Set("mongodb_default_auth_db", *details.MongodbDefaultAuthDb)
		if err != nil {
			return err
		}
	}
	if details.MongodbUriOptions != nil {
		err := d.Set("mongodb_uri_options", *details.MongodbUriOptions)
		if err != nil {
			return err
		}
	}
	if details.MongodbAtlasProjectId != nil {
		err := d.Set("mongodb_atlas_project_id", *details.MongodbAtlasProjectId)
		if err != nil {
			return err
		}
	}
	if details.MongodbAtlasApiPublicKey != nil {
		err := d.Set("mongodb_atlas_api_public_key", *details.MongodbAtlasApiPublicKey)
		if err != nil {
			return err
		}
	}
	if details.MongodbAtlasApiPrivateKey != nil {
		err := d.Set("mongodb_atlas_api_private_key", *details.MongodbAtlasApiPrivateKey)
		if err != nil {
			return err
		}
	}
	if details.MongodbIsAtlas != nil {
		err := d.Set("mongodb_is_atlas", *details.MongodbIsAtlas)
		if err != nil {
			return err
		}
	}

	return nil
}

func setNativeK8sTargetDetails(d *schema.ResourceData, details *akeyless.NativeK8sTargetDetails) error {
	if details.K8sClusterEndpoint != nil {
		err := d.Set("k8s_cluster_endpoint", *details.K8sClusterEndpoint)
		if err != nil {
			return err
		}
	}
	if details.K8sClusterCaCertificate != nil {
		err := d.Set("k8s_cluster_ca_certificate", *details.K8sClusterCaCertificate)
		if err != nil {
			return err
		}
	}
	if details.K8sBearerToken != nil {
		err := d.Set("k8s_bearer_token", *details.K8sBearerToken)
		if err != nil {
			return err
		}
	}
	if details.UseGwServiceAccount != nil {
		err := d.Set("use_gw_cloud_identity", *details.UseGwServiceAccount)
		if err != nil {
			return err
		}
	}

	return nil
}

func setPingTargetDetails(d *schema.ResourceData, details *akeyless.PingTargetDetails) error {
	if details.PingUrl != nil {
		err := d.Set("ping_url", *details.PingUrl)
		if err != nil {
			return err
		}
	}
	if details.PrivilegedUser != nil {
		err := d.Set("ping_privileged_user", *details.PrivilegedUser)
		if err != nil {
			return err
		}
	}
	if details.UserPassword != nil {
		err := d.Set("ping_user_password", *details.UserPassword)
		if err != nil {
			return err
		}
	}
	if details.AdministrativePort != nil {
		err := d.Set("ping_administrative_port", *details.AdministrativePort)
		if err != nil {
			return err
		}
	}
	if details.AuthorizationPort != nil {
		err := d.Set("ping_authorization_port", *details.AuthorizationPort)
		if err != nil {
			return err
		}
	}

	return nil
}

func setRabbitMqTargetDetails(d *schema.ResourceData, details *akeyless.RabbitMQTargetDetails) error {
	if details.RabbitmqServerUser != nil {
		err := d.Set("rabbitmq_server_user", *details.RabbitmqServerUser)
		if err != nil {
			return err
		}
	}
	if details.RabbitmqServerPassword != nil {
		err := d.Set("rabbitmq_server_password", *details.RabbitmqServerPassword)
		if err != nil {
			return err
		}
	}
	if details.RabbitmqServerUri != nil {
		err := d.Set("rabbitmq_server_uri", *details.RabbitmqServerUri)
		if err != nil {
			return err
		}
	}

	return nil
}

func setSalesforceTargetDetails(d *schema.ResourceData, details *akeyless.SalesforceTargetDetails) error {
	if details.AuthFlow != nil {
		err := d.Set("salesforce_auth_flow", *details.AuthFlow)
		if err != nil {
			return err
		}
	}
	if details.UserName != nil {
		err := d.Set("salesforce_user_name", *details.UserName)
		if err != nil {
			return err
		}
	}
	if details.Password != nil {
		err := d.Set("salesforce_password", *details.Password)
		if err != nil {
			return err
		}
	}
	if details.TenantUrl != nil {
		err := d.Set("salesforce_tenant_url", *details.TenantUrl)
		if err != nil {
			return err
		}
	}
	if details.ClientId != nil {
		err := d.Set("salesforce_client_id", *details.ClientId)
		if err != nil {
			return err
		}
	}
	if details.ClientSecret != nil {
		err := d.Set("salesforce_client_secret", *details.ClientSecret)
		if err != nil {
			return err
		}
	}
	if details.SecurityToken != nil {
		err := d.Set("salesforce_security_token", *details.SecurityToken)
		if err != nil {
			return err
		}
	}
	if details.CaCertName != nil {
		err := d.Set("salesforce_ca_cert_name", *details.CaCertName)
		if err != nil {
			return err
		}
	}
	// if details.AppPrivateKey != nil {
	// 	err := d.Set("salesforce_app_private_key", *details.AppPrivateKey)
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	// if details.CaCertData != nil {
	// 	err := d.Set("salesforce_ca_cert_data", *details.CaCertData)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	return nil
}

func setSshTargetDetails(d *schema.ResourceData, details *akeyless.SSHTargetDetails) error {
	if details.Username != nil {
		err := d.Set("ssh_username", *details.Username)
		if err != nil {
			return err
		}
	}
	if details.Password != nil {
		err := d.Set("ssh_password", *details.Password)
		if err != nil {
			return err
		}
	}
	if details.Host != nil {
		err := d.Set("ssh_host", *details.Host)
		if err != nil {
			return err
		}
	}
	if details.Port != nil {
		err := d.Set("ssh_port", *details.Port)
		if err != nil {
			return err
		}
	}
	if details.PrivateKey != nil {
		err := d.Set("ssh_private_key", *details.PrivateKey)
		if err != nil {
			return err
		}
	}
	if details.PrivateKeyPassword != nil {
		err := d.Set("ssh_private_key_password", *details.PrivateKeyPassword)
		if err != nil {
			return err
		}
	}

	return nil
}

func setVenafiTargetDetails(d *schema.ResourceData, details *akeyless.VenafiTargetDetails) error {
	if details.VenafiApiKey != nil {
		err := d.Set("venafi_api_key", *details.VenafiApiKey)
		if err != nil {
			return err
		}
	}
	if details.VenafiZone != nil {
		err := d.Set("venafi_zone", *details.VenafiZone)
		if err != nil {
			return err
		}
	}
	if details.VenafiBaseUrl != nil {
		err := d.Set("venafi_base_url", *details.VenafiBaseUrl)
		if err != nil {
			return err
		}
	}
	if details.VenafiTppAccessToken != nil {
		err := d.Set("venafi_tpp_access_token", *details.VenafiTppAccessToken)
		if err != nil {
			return err
		}
	}
	if details.VenafiTppRefreshToken != nil {
		err := d.Set("venafi_tpp_refresh_token", *details.VenafiTppRefreshToken)
		if err != nil {
			return err
		}
	}
	if details.VenafiTppClientId != nil {
		err := d.Set("venafi_tpp_client_id", *details.VenafiTppClientId)
		if err != nil {
			return err
		}
	}
	if details.VenafiUseTpp != nil {
		err := d.Set("venafi_use_tpp", *details.VenafiUseTpp)
		if err != nil {
			return err
		}
	}

	return nil
}

func setWebTargetDetails(d *schema.ResourceData, details *akeyless.WebTargetDetails) error {
	if details.Url != nil {
		err := d.Set("web_url", *details.Url)
		if err != nil {
			return err
		}
	}

	return nil
}

func setWindowsTargetDetails(d *schema.ResourceData, details *akeyless.WindowsTargetDetails) error {
	if details.Username != nil {
		err := d.Set("windows_username", *details.Username)
		if err != nil {
			return err
		}
	}
	if details.Password != nil {
		err := d.Set("windows_password", *details.Password)
		if err != nil {
			return err
		}
	}
	if details.Hostname != nil {
		err := d.Set("windows_hostname", *details.Hostname)
		if err != nil {
			return err
		}
	}
	if details.Port != nil {
		err := d.Set("windows_port", *details.Port)
		if err != nil {
			return err
		}
	}
	if details.DomainName != nil {
		err := d.Set("windows_domain_name", *details.DomainName)
		if err != nil {
			return err
		}
	}
	if details.Certificate != nil {
		err := d.Set("windows_certificate", *details.Certificate)
		if err != nil {
			return err
		}
	}
	if details.UseTls != nil {
		err := d.Set("windows_use_tls", *details.UseTls)
		if err != nil {
			return err
		}
	}

	return nil
}

func setZerosslTargetDetails(d *schema.ResourceData, details *akeyless.ZeroSSLTargetDetails) error {
	if details.ApiKey != nil {
		err := d.Set("zerossl_api_key", *details.ApiKey)
		if err != nil {
			return err
		}
	}
	if details.ImapUser != nil {
		err := d.Set("zerossl_imap_user", *details.ImapUser)
		if err != nil {
			return err
		}
	}
	if details.ImapPassword != nil {
		err := d.Set("zerossl_imap_password", *details.ImapPassword)
		if err != nil {
			return err
		}
	}
	if details.ImapFqdn != nil {
		err := d.Set("zerossl_imap_fqdn", *details.ImapFqdn)
		if err != nil {
			return err
		}
	}
	if details.ValidationEmail != nil {
		err := d.Set("zerossl_validation_email", *details.ValidationEmail)
		if err != nil {
			return err
		}
	}
	if details.ImapPort != nil {
		err := d.Set("zerossl_imap_port", *details.ImapPort)
		if err != nil {
			return err
		}
	}
	if details.Timeout != nil {
		err := d.Set("timeout", *details.Timeout)
		if err != nil {
			return err
		}
	}

	return nil
}
