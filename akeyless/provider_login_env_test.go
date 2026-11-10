package akeyless

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var loginEnvVars = []string{
	envAccessType, envAccessID, envAccessKey, envEmail, envPassword, envJwt,
	envUidToken, envCertData, envKeyData, envToken, envGcpAudience, envJwtFile,
}

// clearLoginEnv unsets every login environment variable for the duration of the test.
func clearLoginEnv(t *testing.T) {
	t.Helper()
	for _, name := range loginEnvVars {
		t.Setenv(name, "")
	}
}

func emptyProviderData(t *testing.T) *schema.ResourceData {
	t.Helper()
	return schema.TestResourceDataRaw(t, Provider().Schema, map[string]interface{}{})
}

func TestLoginFromEnvByAccessType(t *testing.T) {
	cases := []struct {
		name   string
		env    map[string]string
		want   loginType
		values map[string]string
	}{
		{"api_key", map[string]string{envAccessType: "api_key", envAccessID: "p-1", envAccessKey: "k"}, ApiKeyLogin, map[string]string{"access_id": "p-1", "access_key": "k"}},
		{"access_key alias", map[string]string{envAccessType: "access_key", envAccessID: "p-1", envAccessKey: "k"}, ApiKeyLogin, map[string]string{"access_id": "p-1"}},
		{"password", map[string]string{envAccessType: "password", envEmail: "a@b.c", envPassword: "pw"}, EmailLogin, map[string]string{"admin_email": "a@b.c", "admin_password": "pw"}},
		{"aws_iam", map[string]string{envAccessType: "aws_iam", envAccessID: "p-2"}, AwsIAMLogin, map[string]string{"access_id": "p-2"}},
		{"gcp", map[string]string{envAccessType: "gcp", envAccessID: "p-3", envGcpAudience: "aud"}, GcpIAMLogin, map[string]string{"access_id": "p-3", "audience": "aud"}},
		{"azure_ad", map[string]string{envAccessType: "azure_ad", envAccessID: "p-4"}, AzureADLogin, map[string]string{"access_id": "p-4"}},
		{"jwt", map[string]string{envAccessType: "jwt", envAccessID: "p-5", envJwt: "h.p.s"}, JwtLogin, map[string]string{"access_id": "p-5", "jwt": "h.p.s"}},
		{"universal_identity", map[string]string{envAccessType: "universal_identity", envUidToken: "u"}, UidLogin, map[string]string{"uid_token": "u"}},
		{"cert", map[string]string{envAccessType: "cert", envAccessID: "p-6", envCertData: "c", envKeyData: "k"}, CertLogin, map[string]string{"access_id": "p-6", "cert_data": "c", "key_data": "k"}},
		{"case insensitive", map[string]string{envAccessType: " JWT ", envAccessID: "p-7", envJwt: "h.p.s"}, JwtLogin, map[string]string{"access_id": "p-7"}},
		{"no type, api key", map[string]string{envAccessID: "p-8", envAccessKey: "k"}, ApiKeyLogin, map[string]string{"access_id": "p-8"}},
		{"no type, jwt", map[string]string{envAccessID: "p-9", envJwt: "h.p.s"}, JwtLogin, map[string]string{"access_id": "p-9"}},
		{"no type, api key wins over jwt", map[string]string{envAccessID: "p-10", envAccessKey: "k", envJwt: "h.p.s"}, ApiKeyLogin, map[string]string{"access_id": "p-10"}},
		{"auto", map[string]string{envAccessType: "auto", envAccessID: "p-12", envJwt: "h.p.s"}, JwtLogin, map[string]string{"access_id": "p-12"}},
		{"explicit type wins over api key", map[string]string{envAccessType: "jwt", envAccessID: "p-11", envAccessKey: "k", envJwt: "h.p.s"}, JwtLogin, map[string]string{"access_id": "p-11"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearLoginEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			login, lt, err := getLoginWithValidation(emptyProviderData(t))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if lt != tc.want {
				t.Fatalf("expected %s, got %s", tc.want, lt)
			}
			m := login.(map[string]interface{})
			for k, v := range tc.values {
				if m[k] != v {
					t.Fatalf("expected %s=%q, got %v", k, v, m[k])
				}
			}
		})
	}
}

func TestLoginFromEnvErrors(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"nothing set", map[string]string{}, "please choose supported login method"},
		{"unsupported type", map[string]string{envAccessType: "saml"}, "unsupported access_type"},
		{"jwt and jwt file both set", map[string]string{envAccessType: "jwt", envAccessID: "p-1", envJwt: "h.p.s", envJwtFile: "/tmp/x"}, "set only one of"},
		{"jwt file missing", map[string]string{envAccessType: "jwt", envAccessID: "p-1", envJwtFile: "/nonexistent/token"}, "failed to read"},
		{"jwt missing token", map[string]string{envAccessType: "jwt", envAccessID: "p-1"}, envJwt},
		{"cert missing key", map[string]string{envAccessType: "cert", envAccessID: "p-1", envCertData: "c"}, envKeyData},
		{"token missing token", map[string]string{envAccessType: "token"}, envToken},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearLoginEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, _, err := getLoginWithValidation(emptyProviderData(t))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestLoginBlockTakesPrecedenceOverEnv(t *testing.T) {
	clearLoginEnv(t)
	t.Setenv(envAccessType, "jwt")
	t.Setenv(envAccessID, "p-env")
	t.Setenv(envJwt, "h.p.s")

	d := schema.TestResourceDataRaw(t, Provider().Schema, map[string]interface{}{
		"aws_iam_login": []interface{}{map[string]interface{}{"access_id": "p-block"}},
	})
	login, lt, err := getLoginWithValidation(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lt != AwsIAMLogin || login.(map[string]interface{})["access_id"] != "p-block" {
		t.Fatalf("expected the aws_iam_login block to win, got %s %v", lt, login)
	}
}

func TestLoginBlockAccessIdFromEnv(t *testing.T) {
	for _, block := range []string{"jwt_login", "gcp_login", "aws_iam_login", "azure_ad_login"} {
		t.Run(block, func(t *testing.T) {
			clearLoginEnv(t)
			t.Setenv(envAccessID, "p-env")
			t.Setenv(envJwt, "h.p.s")

			d := schema.TestResourceDataRaw(t, Provider().Schema, map[string]interface{}{
				block: []interface{}{map[string]interface{}{}},
			})
			login, _, err := getLoginWithValidation(d)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := login.(map[string]interface{})["access_id"]; got != "p-env" {
				t.Fatalf("expected access_id from env, got %v", got)
			}
		})
	}
}

func TestTokenFromEnv(t *testing.T) {
	clearLoginEnv(t)
	t.Setenv(envAccessType, "token")
	t.Setenv(envToken, "t-123")

	token, err := getProviderToken(t.Context(), emptyProviderData(t), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "t-123" {
		t.Fatalf("expected token from env, got %q", token)
	}
}

func writeTokenFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoginFromEnvJwtFile(t *testing.T) {
	for _, accessType := range []string{"jwt", ""} {
		t.Run("type="+accessType, func(t *testing.T) {
			clearLoginEnv(t)
			t.Setenv(envAccessType, accessType)
			t.Setenv(envAccessID, "p-file")
			t.Setenv(envJwtFile, writeTokenFile(t, "h.p.s\n"))

			login, lt, err := getLoginWithValidation(emptyProviderData(t))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if lt != JwtLogin || login.(map[string]interface{})["jwt"] != "h.p.s" {
				t.Fatalf("expected jwt from file, got %s %v", lt, login)
			}
		})
	}
}

func TestJwtLoginBlockJwtFromFile(t *testing.T) {
	clearLoginEnv(t)
	t.Setenv(envAccessID, "p-file")
	t.Setenv(envJwtFile, writeTokenFile(t, "h.p.s"))

	d := schema.TestResourceDataRaw(t, Provider().Schema, map[string]interface{}{
		"jwt_login": []interface{}{map[string]interface{}{}},
	})
	login, _, err := getLoginWithValidation(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := login.(map[string]interface{})["jwt"]; got != "h.p.s" {
		t.Fatalf("expected jwt from file, got %v", got)
	}
}

func TestAccessTypeArgumentOverridesEnv(t *testing.T) {
	clearLoginEnv(t)
	t.Setenv(envAccessType, "api_key")
	t.Setenv(envAccessID, "p-arg")
	t.Setenv(envAccessKey, "k")
	t.Setenv(envJwt, "h.p.s")

	d := schema.TestResourceDataRaw(t, Provider().Schema, map[string]interface{}{
		"access_type": "jwt",
	})
	_, lt, err := getLoginWithValidation(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lt != JwtLogin {
		t.Fatalf("expected access_type argument to select %s, got %s", JwtLogin, lt)
	}
}

func TestAuthDataSourceUsesEnv(t *testing.T) {
	clearLoginEnv(t)
	t.Setenv(envAccessType, "jwt")
	t.Setenv(envAccessID, "p-ds")
	t.Setenv(envJwt, "h.p.s")

	d := schema.TestResourceDataRaw(t, dataSourceAuth().Schema, map[string]interface{}{})
	_, lt, err := getLoginWithValidation(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lt != JwtLogin {
		t.Fatalf("expected %s, got %s", JwtLogin, lt)
	}
}
