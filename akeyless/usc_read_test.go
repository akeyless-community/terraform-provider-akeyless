package akeyless

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestSetUscGcpReadFields(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceUsc().Schema, map[string]interface{}{
		"gcp_project_id":      "old-project",
		"gcp_sm_regions":      "us-east1",
		"gcp_scope":           "project",
		"gcp_folder_id":       "old-folder",
		"gcp_organization_id": "old-organization",
	})

	if err := setUscGcpReadFields(d, map[string]string{
		"gcp_project_id":      "project-123",
		"gcp_sm_regions":      "us-east1,us-west1",
		"gcp_scope":           "folder",
		"gcp_folder_id":       "123456",
		"gcp_organization_id": "987654",
	}); err != nil {
		t.Fatalf("setUscGcpReadFields() error = %v", err)
	}
	if got := d.Get("gcp_project_id"); got != "project-123" {
		t.Errorf("gcp_project_id = %q, want project-123", got)
	}
	if got := d.Get("gcp_sm_regions"); got != "us-east1,us-west1" {
		t.Errorf("gcp_sm_regions = %q, want us-east1,us-west1", got)
	}
	if got := d.Get("gcp_scope"); got != "folder" {
		t.Errorf("gcp_scope = %q, want folder", got)
	}
	if got := d.Get("gcp_folder_id"); got != "123456" {
		t.Errorf("gcp_folder_id = %q, want 123456", got)
	}
	if got := d.Get("gcp_organization_id"); got != "987654" {
		t.Errorf("gcp_organization_id = %q, want 987654", got)
	}

	if err := setUscGcpReadFields(d, map[string]string{}); err != nil {
		t.Fatalf("setUscGcpReadFields() clear error = %v", err)
	}
	for _, key := range []string{
		"gcp_project_id",
		"gcp_sm_regions",
		"gcp_scope",
		"gcp_folder_id",
		"gcp_organization_id",
	} {
		if got := d.Get(key); got != "" {
			t.Errorf("%s = %q, want empty after remote removal", key, got)
		}
	}
}
