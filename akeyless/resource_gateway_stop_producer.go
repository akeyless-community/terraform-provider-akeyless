// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceStopProducer() *schema.Resource {
	return &schema.Resource{
		Description: "Producer Stop resource",
		Create:      resourcegatewayStopProducerCreate,
		Read:        resourcegatewayStopProducerRead,
		Update:      resourcegatewayStopProducerUpdate,
		Delete:      resourcegatewayStopProducerDelete,
		Importer: &schema.ResourceImporter{
			State: resourcegatewayStopProducerImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Producer name",
			},
			"stop": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "stop this producer",
			},
		},
	}
}

func resourcegatewayStopProducerCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless.GatewayStopProducer{
		Name:  name,
		Token: &token,
	}

	_, _, err := client.GatewayStopProducer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't stop producer: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't stop producer: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourcegatewayStopProducerRead(d *schema.ResourceData, m interface{}) error {

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
		err = d.Set("stop", !*rOut.Active)
		if err != nil {
			return err
		}
	}

	d.SetId(name)
	return nil
}

func resourcegatewayStopProducerUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless.GatewayStopProducer{
		Name:  name,
		Token: &token,
	}

	_, _, err := client.GatewayStopProducer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't stop producer: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't stop producer: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourcegatewayStopProducerDelete(d *schema.ResourceData, m interface{}) error {

	return nil
}

func resourcegatewayStopProducerImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	path := d.Id()

	err := d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
