// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceStartProducer() *schema.Resource {
	return &schema.Resource{
		Description: "Producer Start resource",
		Create:      resourcegatewayStartProducerCreate,
		Read:        resourcegatewayStartProducerRead,
		Update:      resourcegatewayStartProducerUpdate,
		Delete:      resourcegatewayStartProducerDelete,
		Importer: &schema.ResourceImporter{
			State: resourcegatewayStartProducerImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Producer name",
			},
			"start": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "start this producer",
			},
		},
	}
}

func resourcegatewayStartProducerCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless.GatewayStartProducer{
		Name:  name,
		Token: &token,
	}

	_, _, err := client.GatewayStartProducer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't start producer: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't start producer: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourcegatewayStartProducerRead(d *schema.ResourceData, m interface{}) error {

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless.GatewayGetProducer{
		Name:  name,
		Token: &token,
	}

	rOut, _, err := client.GatewayGetProducer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't get value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}

	if rOut.Active != nil {
		err = d.Set("start", *rOut.Active)
		if err != nil {
			return err
		}
	}

	d.SetId(name)
	return nil
}

func resourcegatewayStartProducerUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless.GatewayStartProducer{
		Name:  name,
		Token: &token,
	}

	_, _, err := client.GatewayStartProducer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't start producer: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't start producer: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourcegatewayStartProducerDelete(d *schema.ResourceData, m interface{}) error {

	return nil
}

func resourcegatewayStartProducerImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	path := d.Id()

	err := d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
