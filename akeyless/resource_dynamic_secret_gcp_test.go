package akeyless

import (
	"context"
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func gcpDynamicSecretRawConfig(attrs map[string]string) cty.Value {
	vals := make(map[string]cty.Value)
	for name, attrType := range resourceDynamicSecretGcp().CoreConfigSchema().ImpliedType().AttributeTypes() {
		vals[name] = cty.NullVal(attrType)
	}
	for name, v := range attrs {
		vals[name] = cty.StringVal(v)
	}
	return cty.ObjectVal(vals)
}

func TestDynamicSecretGcpProjectIdAliasDiff(t *testing.T) {
	const name = "/ds-gcp"
	cases := []struct {
		name        string
		state       map[string]string
		config      map[string]string
		wantChanged map[string]bool
	}{
		{
			name:   "config sets only project_id",
			state:  map[string]string{"project_id": "p1", "gcp_project_id": "p1"},
			config: map[string]string{"project_id": "p1"},
		},
		{
			name:   "config sets only gcp_project_id",
			state:  map[string]string{"project_id": "p1", "gcp_project_id": "p1"},
			config: map[string]string{"gcp_project_id": "p1"},
		},
		{
			name:   "config sets both to the same value",
			state:  map[string]string{"project_id": "p1", "gcp_project_id": "p1"},
			config: map[string]string{"project_id": "p1", "gcp_project_id": "p1"},
		},
		{
			name:        "config removes both",
			state:       map[string]string{"project_id": "p1", "gcp_project_id": "p1"},
			config:      map[string]string{},
			wantChanged: map[string]bool{"project_id": true, "gcp_project_id": true},
		},
		{
			name:        "config changes project_id and drops gcp_project_id",
			state:       map[string]string{"project_id": "p1", "gcp_project_id": "p1"},
			config:      map[string]string{"project_id": "p2"},
			wantChanged: map[string]bool{"project_id": true, "gcp_project_id": true},
		},
		{
			name:        "gateway has no override but config sets project_id",
			state:       map[string]string{"project_id": "", "gcp_project_id": ""},
			config:      map[string]string{"project_id": "p1"},
			wantChanged: map[string]bool{"project_id": true},
		},
	}

	r := resourceDynamicSecretGcp()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configAttrs := map[string]string{"name": name}
			rawConfig := map[string]interface{}{"name": name}
			for k, v := range tc.config {
				configAttrs[k] = v
				rawConfig[k] = v
			}
			stateAttrs := map[string]string{"id": name, "name": name}
			for k, v := range tc.state {
				stateAttrs[k] = v
			}
			state := &terraform.InstanceState{
				ID:         name,
				Attributes: stateAttrs,
				RawConfig:  gcpDynamicSecretRawConfig(configAttrs),
			}

			diff, err := r.Diff(context.Background(), state, terraform.NewResourceConfigRaw(rawConfig), nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, attr := range []string{"project_id", "gcp_project_id"} {
				changed := diff != nil && diff.Attributes[attr] != nil
				if changed != tc.wantChanged[attr] {
					t.Errorf("%s changed = %v, want %v", attr, changed, tc.wantChanged[attr])
				}
			}
		})
	}
}

func TestGetGcpProjectIdOverride(t *testing.T) {
	cases := []struct {
		name   string
		config map[string]interface{}
		want   string
	}{
		{"project_id only", map[string]interface{}{"project_id": "p1"}, "p1"},
		{"gcp_project_id only", map[string]interface{}{"gcp_project_id": "p1"}, "p1"},
		{"both set", map[string]interface{}{"project_id": "p1", "gcp_project_id": "p2"}, "p2"},
		{"neither set", map[string]interface{}{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.config["name"] = "/ds-gcp"
			d := schema.TestResourceDataRaw(t, resourceDynamicSecretGcp().Schema, tc.config)
			if got := getGcpProjectIdOverride(d); got != tc.want {
				t.Errorf("getGcpProjectIdOverride() = %q, want %q", got, tc.want)
			}
		})
	}
}
