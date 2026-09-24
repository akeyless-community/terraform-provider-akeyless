package akeyless

import (
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/stretchr/testify/require"
)

func TestExtractAwsTargetDetails(t *testing.T) {
	value, err := extractAwsTargetDetails(&akeyless_api.AWSTargetDetails{
		AwsAccessKeyId:     targetDetailsPtr("access-key-id"),
		AwsSecretAccessKey: targetDetailsPtr("secret-access-key"),
		AwsSessionToken:    targetDetailsPtr("session-token"),
		AwsUserName:        targetDetailsPtr("user-name"),
		AwsRegion:          targetDetailsPtr("us-east-1"),
		UseGwCloudIdentity: targetDetailsPtr(true),
		GwCloudIdentityExternalIdOpt: &akeyless_api.AWSGatewayCloudIdentityExternalIdOpt{
			GeneratedExternalId: targetDetailsPtr("external-id"),
			IsEnabled:           targetDetailsPtr(true),
			RoleArn:             targetDetailsPtr("arn:aws:iam::123456789012:role/test"),
		},
	})
	require.NoError(t, err)
	requireTargetDetailsJSON(t, value, "aws_target_details", `{
		"access_key_id": "access-key-id",
		"access_key": "secret-access-key",
		"session_token": "session-token",
		"aws_user_name": "user-name",
		"region": "us-east-1",
		"use_gw_cloud_identity": true,
		"gw_cloud_identity_external_id_opt": {
			"generated_external_id": "external-id",
			"is_enabled": true,
			"role_arn": "arn:aws:iam::123456789012:role/test"
		}
	}`)
}

func TestExtractOpenAITargetDetails(t *testing.T) {
	value, err := extractOpenaiTargetDetails(&akeyless_api.OpenAITargetDetails{
		ApiKey:            targetDetailsPtr("api-key"),
		ApiKeyId:          targetDetailsPtr("api-key-id"),
		AuthMode:          targetDetailsPtr("chatgpt_oauth"),
		OauthAccessToken:  targetDetailsPtr("access-token"),
		OauthAccountId:    targetDetailsPtr("account-id"),
		OauthLastRefresh:  targetDetailsPtr("2026-09-24T12:00:00Z"),
		OauthRefreshToken: targetDetailsPtr("refresh-token"),
		OpenaiUrl:         targetDetailsPtr("https://api.openai.com/v1"),
		OrganizationId:    targetDetailsPtr("org-id"),
		ProjectId:         targetDetailsPtr("project-id"),
	})
	require.NoError(t, err)
	requireTargetDetailsJSON(t, value, "openai_target_details", `{
		"api_key": "api-key",
		"api_key_id": "api-key-id",
		"auth_mode": "chatgpt_oauth",
		"oauth_access_token": "access-token",
		"oauth_account_id": "account-id",
		"oauth_last_refresh": "2026-09-24T12:00:00Z",
		"oauth_refresh_token": "refresh-token",
		"openai_url": "https://api.openai.com/v1",
		"organization_id": "org-id",
		"project_id": "project-id"
	}`)
}

func TestExtractAerospikeTargetDetails(t *testing.T) {
	value, err := extractAerospikeTargetDetails(&akeyless_api.AerospikeTargetDetails{
		AerospikeAdminUsername:            targetDetailsPtr("admin"),
		AerospikePassword:                 targetDetailsPtr("password"),
		AerospikeHostname:                 targetDetailsPtr("aerospike.example.com"),
		AerospikePort:                     targetDetailsPtr("3000"),
		AerospikeNamespace:                targetDetailsPtr("test"),
		AerospikeCloud:                    targetDetailsPtr(false),
		AerospikeClientId:                 targetDetailsPtr("client-id"),
		AerospikeClientSecret:             targetDetailsPtr("client-secret"),
		AerospikeClusterId:                targetDetailsPtr("cluster-id"),
		AerospikeSslConnectionMode:        targetDetailsPtr(true),
		AerospikeSslConnectionCertificate: targetDetailsPtr("certificate"),
		AerospikeDbServerName:             targetDetailsPtr("aerospike.example.com"),
		AerospikeSkipServerNameValidation: targetDetailsPtr("false"),
		AerospikeEnableMtls:               targetDetailsPtr(true),
		AerospikeClientCertificate:        targetDetailsPtr("client-certificate"),
		AerospikeClientPrivateKey:         targetDetailsPtr("client-private-key"),
	})
	require.NoError(t, err)
	requireTargetDetailsJSON(t, value, "aerospike_target_details", `{
		"admin_username": "admin",
		"password": "password",
		"hostname": "aerospike.example.com",
		"port": "3000",
		"namespace": "test",
		"aerospike_cloud": false,
		"aerospike_client_id": "client-id",
		"aerospike_client_secret": "client-secret",
		"aerospike_cluster_id": "cluster-id",
		"ssl": true,
		"ssl_certificate": "certificate",
		"db_server_name": "aerospike.example.com",
		"skip_server_name_validation": "false",
		"enable_mtls": true,
		"client_certificate": "client-certificate",
		"client_private_key": "client-private-key"
	}`)
}

func TestExtractF5BigIpTargetDetails(t *testing.T) {
	value, err := extractF5BigIpTargetDetails(&akeyless_api.F5BigIpTargetDetails{
		Url:      targetDetailsPtr("https://f5.example.com"),
		Username: targetDetailsPtr("admin"),
		Password: targetDetailsPtr("password"),
	})
	require.NoError(t, err)
	requireTargetDetailsJSON(t, value, "f5_big_ip_target_details", `{
		"url": "https://f5.example.com",
		"username": "admin",
		"password": "password"
	}`)
}

func requireTargetDetailsJSON(t *testing.T, value map[string]string, targetType, want string) {
	t.Helper()
	require.JSONEq(t, want, value[targetType])
}

func targetDetailsPtr[T any](value T) *T {
	return &value
}
