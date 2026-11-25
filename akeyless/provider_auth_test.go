package akeyless

import (
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Verify Framework authentication environment fallbacks.

func newProviderResourceData(t *testing.T, raw map[string]interface{}) *schema.ResourceData {
	t.Helper()
	return schema.TestResourceDataRaw(t, Provider().Schema, raw)
}

func TestApiKeyLogin_FallsBackToEnvVars(t *testing.T) {
	t.Setenv("AKEYLESS_ACCESS_ID", "p-env")
	t.Setenv("AKEYLESS_ACCESS_KEY", "key-env")

	// Exercise setAuthBody directly because an empty nested SDK block is omitted.
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

func TestJwtLogin_AccessIdFallsBackToEnvVar(t *testing.T) {
	t.Setenv("AKEYLESS_ACCESS_ID", "p-env")

	d := newProviderResourceData(t, map[string]interface{}{
		"jwt_login": []interface{}{map[string]interface{}{
			"jwt": "jwt-1",
		}},
	})

	authBody, err := getAuthInfo(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authBody.GetAccessId() != "p-env" || authBody.GetJwt() != "jwt-1" {
		t.Fatalf("got access_id=%q jwt=%q, want p-env and jwt-1", authBody.GetAccessId(), authBody.GetJwt())
	}
}

func TestJwtLogin_BlockValueWinsOverEnvVar(t *testing.T) {
	t.Setenv("AKEYLESS_ACCESS_ID", "p-env")
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
	if authBody.GetAccessId() != "p-1" {
		t.Fatalf("got access_id=%q, want p-1", authBody.GetAccessId())
	}
}

func TestNoLoginBlock_UsesJwtFromEnvVars(t *testing.T) {
	t.Setenv("AKEYLESS_ACCESS_ID", "p-env")
	t.Setenv("AKEYLESS_ACCESS_KEY", "")
	t.Setenv("AKEYLESS_AUTH_JWT", "jwt-env")

	authBody, err := getAuthInfo(newProviderResourceData(t, map[string]interface{}{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authBody.GetAccessType() != common.Jwt || authBody.GetAccessId() != "p-env" || authBody.GetJwt() != "jwt-env" {
		t.Fatalf("got access_type=%q access_id=%q jwt=%q, want jwt login from env", authBody.GetAccessType(), authBody.GetAccessId(), authBody.GetJwt())
	}
}

func TestNoLoginBlock_ApiKeyWinsOverJwt(t *testing.T) {
	t.Setenv("AKEYLESS_ACCESS_ID", "p-env")
	t.Setenv("AKEYLESS_ACCESS_KEY", "key-env")
	t.Setenv("AKEYLESS_AUTH_JWT", "jwt-env")

	authBody, err := getAuthInfo(newProviderResourceData(t, map[string]interface{}{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authBody.GetAccessType() != common.ApiKey {
		t.Fatalf("got access_type=%q, want api key login", authBody.GetAccessType())
	}
}

func TestJwtLogin_MissingAccessIdFails(t *testing.T) {
	t.Setenv("AKEYLESS_ACCESS_ID", "")

	d := newProviderResourceData(t, map[string]interface{}{
		"jwt_login": []interface{}{map[string]interface{}{
			"jwt": "jwt-1",
		}},
	})

	if _, err := getAuthInfo(d); err == nil {
		t.Fatal("want an error when access_id is missing")
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
