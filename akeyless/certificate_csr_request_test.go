package akeyless

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestCertificateDataSourceSendsCertificateRequestOptions(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/get-certificate-value" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}

		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		if got := body["include-private-key"]; got != true {
			t.Errorf("include-private-key = %v, want true", got)
		}
		if got := body["leaf-only"]; got != true {
			t.Errorf("leaf-only = %v, want true", got)
		}
		if got := body["password"]; got != "test-password" {
			t.Errorf("password = %v, want test-password", got)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"certificate_pem": "certificate"})
	}))
	defer server.Close()

	data := schema.TestResourceDataRaw(t, dataSourceCertificate().Schema, map[string]interface{}{
		"name":                "certificate-name",
		"include_private_key": true,
		"leaf_only":           true,
		"password":            "test-password",
	})

	if err := dataSourceGetCertificateValueRead(data, testProviderMeta(server.URL)); err != nil {
		t.Fatalf("read certificate data source: %v", err)
	}
}

func TestCertificateResourceReadSendsCertificateRequestOptions(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/describe-item":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		case "/get-certificate-value":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode request body: %v", err)
			}

			if got := body["include-private-key"]; got != true {
				t.Errorf("include-private-key = %v, want true", got)
			}
			if got := body["leaf-only"]; got != true {
				t.Errorf("leaf-only = %v, want true", got)
			}
			if got := body["password"]; got != "test-password" {
				t.Errorf("password = %v, want test-password", got)
			}

			_ = json.NewEncoder(w).Encode(map[string]string{"certificate_pem": "certificate"})
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	data := schema.TestResourceDataRaw(t, resourceCertificate().Schema, map[string]interface{}{
		"name":                "certificate-name",
		"include_private_key": true,
		"leaf_only":           true,
		"password":            "test-password",
	})
	data.SetId("certificate-name")

	if err := resourceCertificateRead(data, testProviderMeta(server.URL)); err != nil {
		t.Fatalf("read certificate resource: %v", err)
	}
}

func TestCsrDataSourceSendsKeyUsageOptions(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/generate-csr" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}

		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}

		if got := body["customer-frg-id"]; got != "customer-fragment-id" {
			t.Errorf("customer-frg-id = %v, want customer-fragment-id", got)
		}
		if got := body["ext-key-usage"]; got != "clientauth" {
			t.Errorf("ext-key-usage = %v, want clientauth", got)
		}
		if got := body["key-usage"]; got != "DigitalSignature,KeyEncipherment" {
			t.Errorf("key-usage = %v, want DigitalSignature,KeyEncipherment", got)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"data": "csr"})
	}))
	defer server.Close()

	data := schema.TestResourceDataRaw(t, dataSourceGenerateCsr().Schema, map[string]interface{}{
		"name":            "key-name",
		"common_name":     "example.com",
		"key_type":        "dfc",
		"customer_frg_id": "customer-fragment-id",
		"ext_key_usage":   "clientauth",
		"key_usage":       "DigitalSignature,KeyEncipherment",
	})

	if err := dataSourceGenerateCsrRead(data, testProviderMeta(server.URL)); err != nil {
		t.Fatalf("read CSR data source: %v", err)
	}
}

func testProviderMeta(serverURL string) *providerMeta {
	token := "token"
	client := akeyless_api.NewAPIClient(&akeyless_api.Configuration{
		Servers: []akeyless_api.ServerConfiguration{{URL: serverURL}},
	}).V2Api

	return &providerMeta{
		client: client,
		token:  &token,
	}
}
