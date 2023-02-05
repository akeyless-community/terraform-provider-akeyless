package common

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

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
