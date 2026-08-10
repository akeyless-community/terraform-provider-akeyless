package common

import (
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func writeOnlyTestResource() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"mysql_password": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"mysql_password_wo": {
				Type:      schema.TypeString,
				Optional:  true,
				WriteOnly: true,
			},
			"mysql_password_wo_version": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"tls_certificate": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"tls_certificate_wo": {
				Type:      schema.TypeString,
				Optional:  true,
				WriteOnly: true,
			},
		},
	}
}

func TestUsingWriteOnly_WoVersionInState(t *testing.T) {
	d := writeOnlyTestResource().Data(nil)
	if err := d.Set("mysql_password_wo_version", 1); err != nil {
		t.Fatal(err)
	}
	if !UsingWriteOnly(d, "mysql_password_wo", "mysql_password_wo_version") {
		t.Fatal("expected UsingWriteOnly true when wo_version is set")
	}
}

func TestUsingWriteOnly_LegacyPath(t *testing.T) {
	d := writeOnlyTestResource().Data(nil)
	if err := d.Set("mysql_password", "secret"); err != nil {
		t.Fatal(err)
	}
	if UsingWriteOnly(d, "mysql_password_wo", "mysql_password_wo_version") {
		t.Fatal("expected UsingWriteOnly false for legacy password-only config")
	}
}

func TestSetSecretFromRead_ClearsOnWriteOnlyPath(t *testing.T) {
	d := writeOnlyTestResource().Data(nil)
	if err := d.Set("mysql_password_wo_version", 2); err != nil {
		t.Fatal(err)
	}
	if err := SetSecretFromRead(d, "mysql_password", "mysql_password_wo", "mysql_password_wo_version", "from-api"); err != nil {
		t.Fatal(err)
	}
	if got := d.Get("mysql_password").(string); got != "" {
		t.Fatalf("expected empty password in state on WO path, got %q", got)
	}
}

func TestSetSecretFromRead_SetsOnLegacyPath(t *testing.T) {
	d := writeOnlyTestResource().Data(nil)
	if err := SetSecretFromRead(d, "mysql_password", "mysql_password_wo", "mysql_password_wo_version", "from-api"); err != nil {
		t.Fatal(err)
	}
	if got := d.Get("mysql_password").(string); got != "from-api" {
		t.Fatalf("expected password from API on legacy path, got %q", got)
	}
}

func TestSecretValueForUpdate_OmitsMissingWriteOnlyValue(t *testing.T) {
	d := writeOnlyTestResource().Data(nil)
	if err := d.Set("mysql_password_wo_version", 1); err != nil {
		t.Fatal(err)
	}

	value, err := SecretValueForUpdate(d, "mysql_password", "mysql_password_wo")
	if err != nil {
		t.Fatal(err)
	}
	if value != nil {
		t.Fatalf("expected nil value, got %q", *value)
	}
}

func TestSecretValueForUpdate_PreservesLegacyValue(t *testing.T) {
	d := writeOnlyTestResource().Data(nil)
	if err := d.Set("mysql_password", "legacy-secret"); err != nil {
		t.Fatal(err)
	}

	value, err := SecretValueForUpdate(d, "mysql_password", "mysql_password_wo")
	if err != nil {
		t.Fatal(err)
	}
	if value == nil || *value != "legacy-secret" {
		t.Fatalf("expected legacy value, got %v", value)
	}
}

func TestRawString_UnknownValue(t *testing.T) {
	if _, ok := rawString(cty.UnknownVal(cty.String)); ok {
		t.Fatal("expected unknown value to be ignored")
	}
}

func TestRequiredSecretValueForUpdate_RejectsMissingWriteOnlyValue(t *testing.T) {
	d := writeOnlyTestResource().Data(nil)
	if err := d.Set("mysql_password_wo_version", 1); err != nil {
		t.Fatal(err)
	}

	if _, err := RequiredSecretValueForUpdate(d, "mysql_password", "mysql_password_wo"); err == nil {
		t.Fatal("expected error for missing write-only value")
	}
}

// Refresh/import with empty raw config must fall back to the legacy value.
func TestEffectiveSecretValue_EmptyRawConfigFallsBack(t *testing.T) {
	d := writeOnlyTestResource().Data(nil)
	if err := d.Set("tls_certificate", "legacy-cert"); err != nil {
		t.Fatal(err)
	}
	got, err := EffectiveSecretValue(d, "tls_certificate", "tls_certificate_wo")
	if err != nil {
		t.Fatalf("expected no error on empty raw config, got %v", err)
	}
	if got != "legacy-cert" {
		t.Fatalf("expected legacy fallback, got %q", got)
	}
}
