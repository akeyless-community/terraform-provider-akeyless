package akeyless

import (
	"context"
	"fmt"
	"os"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
)

// ApiClient is the authenticated Akeyless handle shared by the SDK v2 and
// Framework providers. Kept tiny on purpose — just what ephemeral Open needs.
type ApiClient struct {
	Client *akeyless_api.V2ApiService
	Token  string
}

// ResolveGateway applies config → AKEYLESS_GATEWAY → public API fallback.
func ResolveGateway(apiGateway string) string {
	if apiGateway == "" {
		apiGateway = os.Getenv("AKEYLESS_GATEWAY")
	}
	if apiGateway == "" {
		apiGateway = publicApi
	}
	return apiGateway
}

// NewV2Api builds an unauthenticated V2 API client pointed at apiGateway.
func NewV2Api(apiGateway string) *akeyless_api.V2ApiService {
	return akeyless_api.NewAPIClient(&akeyless_api.Configuration{
		Servers: []akeyless_api.ServerConfiguration{{
			URL: ResolveGateway(apiGateway),
		}},
		DefaultHeader: map[string]string{common.ClientTypeHeader: common.TerraformClientType},
		HTTPClient:    common.NewRetryHTTPClient(3),
	}).V2Api
}

// NewApiClientWithToken returns a client that already has a token (token_login).
func NewApiClientWithToken(apiGateway, token string) (*ApiClient, error) {
	token = withEnvFallback(token, "AKEYLESS_AUTH_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("token is required (set it directly or via AKEYLESS_AUTH_TOKEN)")
	}
	return &ApiClient{Client: NewV2Api(apiGateway), Token: token}, nil
}

// NewApiClient authenticates with the given login block and returns a client.
// loginAttrs must be the same map shape used by the SDK login schemas
// (e.g. {"access_id": "...", "access_key": "..."} for api_key_login).
func NewApiClient(ctx context.Context, apiGateway string, authType LoginType, loginAttrs map[string]interface{}) (*ApiClient, error) {
	client := NewV2Api(apiGateway)
	authBody := akeyless_api.NewAuthWithDefaults()
	if err := setAuthBody(authBody, loginAttrs, authType); err != nil {
		return nil, err
	}
	authOut, resp, err := client.Auth(ctx).Body(*authBody).Execute()
	if err != nil {
		return nil, common.HandleError("authentication failed", resp, err)
	}
	return &ApiClient{Client: client, Token: authOut.GetToken()}, nil
}
