package akeyless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceRole() *schema.Resource {
	return &schema.Resource{
		Description: "Role data source",
		Read:        dataSourceRoleRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Role name",
			},
			"assoc_auth_method_with_rules": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func dataSourceRoleRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	name := d.Get("name").(string)

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	body := akeyless.GetRole{
		Name:  name,
		Token: &token,
	}

	role, _, err := client.GetRole(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't get Role value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get Role value: %v", err)
	}

	d.SetId(name)

	roleAsJson, err := json.Marshal(role)
	if err != nil {
		return err
	}

	err = d.Set("assoc_auth_method_with_rules", string(roleAsJson))
	if err != nil {
		return err
	}

	return nil
}
