package common

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestUsingWriteOnly_WoVersionInState(t *testing.T) {
	r := &schema.Resource{
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
		},
	}

	d := r.Data(nil)
	if err := d.Set("mysql_password_wo_version", 1); err != nil {
		t.Fatal(err)
	}
	if !UsingWriteOnly(d, "mysql_password_wo", "mysql_password_wo_version") {
		t.Fatal("expected UsingWriteOnly true when wo_version is set")
	}
}

func TestUsingWriteOnly_LegacyPath(t *testing.T) {
	r := &schema.Resource{
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
		},
	}

	d := r.Data(nil)
	if err := d.Set("mysql_password", "secret"); err != nil {
		t.Fatal(err)
	}
	if UsingWriteOnly(d, "mysql_password_wo", "mysql_password_wo_version") {
		t.Fatal("expected UsingWriteOnly false for legacy password-only config")
	}
}

func TestSetSecretFromRead_ClearsOnWriteOnlyPath(t *testing.T) {
	r := &schema.Resource{
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
		},
	}

	d := r.Data(nil)
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
	r := &schema.Resource{
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
		},
	}

	d := r.Data(nil)
	if err := SetSecretFromRead(d, "mysql_password", "mysql_password_wo", "mysql_password_wo_version", "from-api"); err != nil {
		t.Fatal(err)
	}
	if got := d.Get("mysql_password").(string); got != "from-api" {
		t.Fatalf("expected password from API on legacy path, got %q", got)
	}
}
