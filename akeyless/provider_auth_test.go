package akeyless

import (
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// These tests lock in that removing schema.DefaultFunc from the login blocks
// (required so the schema can be mirrored exactly by a muxed
// terraform-plugin-framework provider) did not change observable behavior:
// direct config values still win, env vars still act as a fallback, and a
// clear error is still returned when neither is set.

func newProviderResourceData(t *testing.T, raw map[string]interface{}) *schema.ResourceData {
	t.Helper()
	return schema.TestResourceDataRaw(t, Provider().Schema, raw)
}

func TestApiKeyLogin_DirectValuesWin(t *testing.T) {
	d := newProviderResourceData(t, map[string]interface{}{
		"api_key_login": []interface{}{map[string]interface{}{
			"access_id":  "p-direct",
			"access_key": "key-direct",
		}},
	})

	authBody, err := getAuthInfo(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authBody.GetAccessId() != "p-direct" || authBody.GetAccessKey() != "key-direct" {
		t.Fatalf("got access_id=%q access_key=%q, want direct config values", authBody.GetAccessId(), authBody.GetAccessKey())
	}
}

func TestApiKeyLogin_FallsBackToEnvVars(t *testing.T) {
	t.Setenv("AKEYLESS_ACCESS_ID", "p-env")
	t.Setenv("AKEYLESS_ACCESS_KEY", "key-env")

	// Fields omitted, same as a user writing `api_key_login {}`. setAuthBody
	// is exercised directly (rather than round-tripping through
	// schema.TestResourceDataRaw) because SDK v2's raw-config reader
	// collapses a nested block when every field in it is zero-value.
	authBody := akeyless_api.NewAuthWithDefaults()
	err := setAuthBody(authBody, map[string]interface{}{
		"access_id":  "",
		"access_key": "",
	}, ApiKeyLogin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authBody.GetAccessId() != "p-env" || authBody.GetAccessKey() != "key-env" {
		t.Fatalf("got access_id=%q access_key=%q, want env fallback values", authBody.GetAccessId(), authBody.GetAccessKey())
	}
}

func TestApiKeyLogin_MissingEverythingErrors(t *testing.T) {
	d := newProviderResourceData(t, map[string]interface{}{
		"api_key_login": []interface{}{map[string]interface{}{}},
	})

	if _, err := getAuthInfo(d); err == nil {
		t.Fatal("expected an error when neither config nor env vars provide access_id/access_key")
	}
}

func TestEmailLogin_FallsBackToEnvVars(t *testing.T) {
	t.Setenv("AKEYLESS_EMAIL", "admin@env.example")
	t.Setenv("AKEYLESS_PASSWORD", "pw-env")

	authBody := akeyless_api.NewAuthWithDefaults()
	err := setAuthBody(authBody, map[string]interface{}{
		"admin_email":    "",
		"admin_password": "",
	}, EmailLogin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authBody.GetAdminEmail() != "admin@env.example" || authBody.GetAdminPassword() != "pw-env" {
		t.Fatalf("got admin_email=%q admin_password=%q, want env fallback values", authBody.GetAdminEmail(), authBody.GetAdminPassword())
	}
}

func TestJwtLogin_FallsBackToEnvVar(t *testing.T) {
	t.Setenv("AKEYLESS_AUTH_JWT", "jwt-env")

	d := newProviderResourceData(t, map[string]interface{}{
		"jwt_login": []interface{}{map[string]interface{}{
			"access_id": "p-1",
		}},
	})

	authBody, err := getAuthInfo(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authBody.GetJwt() != "jwt-env" {
		t.Fatalf("got jwt=%q, want env fallback value", authBody.GetJwt())
	}
}

func TestUidLogin_FallsBackToEnvVar(t *testing.T) {
	t.Setenv("AKEYLESS_AUTH_UID", "uid-env")

	d := newProviderResourceData(t, map[string]interface{}{
		"uid_login": []interface{}{map[string]interface{}{
			"access_id": "p-1",
			"uid_token": "",
		}},
	})

	authBody, err := getAuthInfo(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authBody.GetUidToken() != "uid-env" {
		t.Fatalf("got uid_token=%q, want env fallback value", authBody.GetUidToken())
	}
}

func TestCertLogin_FallsBackToEnvVars(t *testing.T) {
	t.Setenv("AKEYLESS_AUTH_CERT", "cert-env")
	t.Setenv("AKEYLESS_AUTH_KEY", "key-env")

	d := newProviderResourceData(t, map[string]interface{}{
		"cert_login": []interface{}{map[string]interface{}{
			"access_id": "p-1",
		}},
	})

	authBody, err := getAuthInfo(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authBody.GetCertData() != "cert-env" || authBody.GetKeyData() != "key-env" {
		t.Fatalf("got cert_data=%q key_data=%q, want env fallback values", authBody.GetCertData(), authBody.GetKeyData())
	}
}

func TestTokenLogin_FallsBackToEnvVar(t *testing.T) {
	t.Setenv("AKEYLESS_AUTH_TOKEN", "token-env")

	token, err := extractTokenFromInput([]interface{}{map[string]interface{}{
		"token": "",
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "token-env" {
		t.Fatalf("got token=%q, want env fallback value", token)
	}
}

func TestTokenLogin_MissingErrors(t *testing.T) {
	_, err := extractTokenFromInput([]interface{}{map[string]interface{}{
		"token": "",
	}})
	if err == nil {
		t.Fatal("expected an error when neither config nor env var provides token")
	}
}

func TestApiGatewayAddress_DefaultsToPublicApi(t *testing.T) {
	d := newProviderResourceData(t, map[string]interface{}{})

	if got := resolveApiGatewayAddress(d); got != publicApi {
		t.Fatalf("got api_gateway_address=%q, want default %q", got, publicApi)
	}
}

func TestApiGatewayAddress_FallsBackToEnvVar(t *testing.T) {
	t.Setenv("AKEYLESS_GATEWAY", "http://env-gateway.example:8080")

	d := newProviderResourceData(t, map[string]interface{}{})

	if got := resolveApiGatewayAddress(d); got != "http://env-gateway.example:8080" {
		t.Fatalf("got api_gateway_address=%q, want env fallback value", got)
	}
}

func TestApiGatewayAddress_DirectValueWins(t *testing.T) {
	t.Setenv("AKEYLESS_GATEWAY", "http://env-gateway.example:8080")

	d := newProviderResourceData(t, map[string]interface{}{
		"api_gateway_address": "http://direct-gateway.example:9090",
	})

	if got := resolveApiGatewayAddress(d); got != "http://direct-gateway.example:9090" {
		t.Fatalf("got api_gateway_address=%q, want direct config value", got)
	}
}
