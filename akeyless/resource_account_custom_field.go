// generated file
package akeyless

import (
	"context"
	"fmt"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAccountCustomField() *schema.Resource {
	return &schema.Resource{
		Description: "Account Custom Field resource",
		Create:      resourceAccountCustomFieldCreate,
		Read:        resourceAccountCustomFieldRead,
		Update:      resourceAccountCustomFieldUpdate,
		Delete:      resourceAccountCustomFieldDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAccountCustomFieldImport,
		},
		Schema: map[string]*schema.Schema{
			"object": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The object the custom field applies to",
				Default:     "ITEM",
			},
			"object_type": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The type of object [STATIC_SECRET, DYNAMIC_SECRET, ROTATED_SECRET]",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the custom field",
			},
			"required": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether the custom field is mandatory",
			},
		},
	}
}

func resourceAccountCustomFieldCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	object := d.Get("object").(string)
	objectType := d.Get("object_type").(string)
	name := d.Get("name").(string)
	required := d.Get("required").(bool)

	body := akeyless_api.AccountCustomFieldCreate{
		Object:     object,
		ObjectType: objectType,
		Name:       name,
		Token:      &token,
	}
	common.GetAkeylessPtr(&body.Required, required)

	ctx := context.Background()
	rOut, resp, err := client.AccountCustomFieldCreate(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create account custom field", resp, err)
	}

	if rOut.Id == nil {
		return fmt.Errorf("account custom field create response missing id")
	}
	d.SetId(strconv.FormatInt(*rOut.Id, 10))

	return nil
}

func resourceAccountCustomFieldRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	parsedId, err := strconv.ParseInt(d.Id(), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid custom field id %q: %w", d.Id(), err)
	}

	body := akeyless_api.AccountCustomFieldGet{
		Id:    parsedId,
		Token: &token,
	}

	ctx := context.Background()
	rOut, resp, err := client.AccountCustomFieldGet(ctx).Body(body).Execute()
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			d.SetId("")
			return nil
		}
		return common.HandleError("can't get account custom field", resp, err)
	}

	if rOut.Object != nil {
		if err := d.Set("object", *rOut.Object); err != nil {
			return err
		}
	}
	if rOut.ObjectType != nil {
		if err := d.Set("object_type", *rOut.ObjectType); err != nil {
			return err
		}
	}
	if rOut.Name != nil {
		if err := d.Set("name", *rOut.Name); err != nil {
			return err
		}
	}
	if rOut.Required != nil {
		if err := d.Set("required", *rOut.Required); err != nil {
			return err
		}
	}

	return nil
}

func resourceAccountCustomFieldUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	parsedId, err := strconv.ParseInt(d.Id(), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid custom field id %q: %w", d.Id(), err)
	}

	name := d.Get("name").(string)
	required := d.Get("required").(bool)

	body := akeyless_api.AccountCustomFieldUpdate{
		Id:    parsedId,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Name, name)
	common.GetAkeylessPtr(&body.Required, required)

	ctx := context.Background()
	_, resp, err := client.AccountCustomFieldUpdate(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update account custom field", resp, err)
	}

	return nil
}

func resourceAccountCustomFieldDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	parsedId, err := strconv.ParseInt(d.Id(), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid custom field id %q: %w", d.Id(), err)
	}

	body := akeyless_api.AccountCustomFieldDelete{
		Id:    parsedId,
		Token: &token,
	}

	ctx := context.Background()
	_, resp, err := client.AccountCustomFieldDelete(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't delete account custom field", resp, err)
	}

	return nil
}

func resourceAccountCustomFieldImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	parsedId, err := strconv.ParseInt(d.Id(), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid custom field id %q: %w", d.Id(), err)
	}

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	body := akeyless_api.AccountCustomFieldGet{
		Id:    parsedId,
		Token: &token,
	}

	ctx := context.Background()
	rOut, resp, err := client.AccountCustomFieldGet(ctx).Body(body).Execute()
	if err != nil {
		return nil, common.HandleError("can't get account custom field", resp, err)
	}

	if rOut.Name != nil {
		if err := d.Set("name", *rOut.Name); err != nil {
			return nil, err
		}
	}
	if rOut.Object != nil {
		if err := d.Set("object", *rOut.Object); err != nil {
			return nil, err
		}
	}
	if rOut.ObjectType != nil {
		if err := d.Set("object_type", *rOut.ObjectType); err != nil {
			return nil, err
		}
	}
	if rOut.Required != nil {
		if err := d.Set("required", *rOut.Required); err != nil {
			return nil, err
		}
	}

	return []*schema.ResourceData{d}, nil
}
