package common

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const testPrivateKeyPEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----\n"

func privateKeyTestResource() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"key_data_base64":            {Type: schema.TypeString, Optional: true},
			"key_data_base64_wo":         {Type: schema.TypeString, Optional: true, WriteOnly: true},
			"key_data_base64_wo_version": {Type: schema.TypeInt, Optional: true},
		},
	}
}

// fakeRotatedValueClient serves rotated-secret-get-value with the stored key in PEM form, as the API does.
func fakeRotatedValueClient(t *testing.T) akeyless_api.V2ApiService {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": map[string]any{"private_key": testPrivateKeyPEM}})
	}))
	t.Cleanup(server.Close)
	return *akeyless_api.NewAPIClient(&akeyless_api.Configuration{
		Servers: []akeyless_api.ServerConfiguration{{URL: server.URL}},
	}).V2Api
}

func TestPrivateKeyForRotatedUpdate_ReloadedKeyIsBase64(t *testing.T) {
	d := privateKeyTestResource().Data(nil)
	if err := d.Set("key_data_base64_wo_version", 1); err != nil { // write-only path, version unchanged
		t.Fatal(err)
	}

	got, err := PrivateKeyForRotatedUpdate(context.Background(), fakeRotatedValueClient(t), "t", "rs", d, "key_data_base64", "key_data_base64_wo")
	if err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString([]byte(testPrivateKeyPEM))
	if got == nil || *got != want {
		t.Fatalf("expected reloaded key base64-encoded %q, got %q", want, deref(got))
	}
}

func TestPrivateKeyForRotatedUpdate_LegacyValueUnchanged(t *testing.T) {
	d := privateKeyTestResource().Data(nil)
	legacy := base64.StdEncoding.EncodeToString([]byte(testPrivateKeyPEM))
	if err := d.Set("key_data_base64", legacy); err != nil {
		t.Fatal(err)
	}

	got, err := PrivateKeyForRotatedUpdate(context.Background(), fakeRotatedValueClient(t), "t", "rs", d, "key_data_base64", "key_data_base64_wo")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got != legacy {
		t.Fatalf("expected config value sent as-is (no double encoding), got %q", deref(got))
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
