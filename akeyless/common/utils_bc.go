package common

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

const (
	DefaultMetadata string = "default_metadata"
	DefaultComment  string = "default_comment"
)

func SetDescriptionBc(d *schema.ResourceData, description string) error {

	if d.HasChange("description") {
		err := d.Set("description", description)
		if err != nil {
			return err
		}
	}

	// BC: terraform provider v1.2.0
	if d.HasChange("comment") {
		err := d.Set("comment", description)
		if err != nil {
			return err
		}
	}

	// BC: terraform provider v1.2.0
	if d.HasChange("metadata") {
		err := d.Set("metadata", description)
		if err != nil {
			return err
		}
	}

	return nil
}

func GetItemDescription(d *schema.ResourceData) string {

	if d.Get("description").(string) != "" {
		return d.Get("description").(string)
	}
	return d.Get("metadata").(string)
}

func GetRoleDescription(d *schema.ResourceData) string {

	if d.Get("description").(string) != "" {
		return d.Get("description").(string)
	}
	return d.Get("comment").(string)
}
