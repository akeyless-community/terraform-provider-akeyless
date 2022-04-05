// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceProducerCustom() *schema.Resource {
	return &schema.Resource{
		Description: "Custom Service producer resource",
		Create:      resourceProducerCustomCreate,
		Read:        resourceProducerCustomRead,
		Update:      resourceProducerCustomUpdate,
		Delete:      resourceProducerCustomDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerCustomImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Producer name",
				ForceNew:    true,
			},
			"create_sync_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "xxx",
			},
			"revoke_sync_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "URL of an endpoint that implements /sync/revoke method, for example https://webhook.example.com/sync/revoke",
			},
			"rotate_sync_url": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "URL of an endpoint that implements /sync/rotate method, for example https://webhook.example.com/sync/rotate",
			},
			"payload": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Secret payload to be sent with each create/revoke webhook request",
			},
			"timeout_sec": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "Maximum allowed time in seconds for the webhook to return the results",
			},
			"producer_encryption_key_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Encrypt producer with following key",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"tags": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: --tag Tag1 --tag Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceProducerCustomCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	createSyncUrl := d.Get("create_sync_url").(string)
	name := d.Get("name").(string)
	payload := d.Get("payload").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	revokeSyncUrl := d.Get("revoke_sync_url").(string)
	rotateSyncUrl := d.Get("rotate_sync_url").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	timeoutSec := d.Get("timeout_sec").(int)
	userTtl := d.Get("user_ttl").(string)

	body := akeyless.GatewayCreateProducerCustom{
		CreateSyncUrl:             createSyncUrl,
		Name:                      name,
		Payload:                   &payload,
		ProducerEncryptionKeyName: &producerEncryptionKeyName,
		RevokeSyncUrl:             revokeSyncUrl,
		RotateSyncUrl:             &rotateSyncUrl,
		Tags:                      &tags,
		TimeoutSec:                akeyless.PtrInt64(int64(timeoutSec)),
		Token:                     &token,
		UserTtl:                   &userTtl,
	}

	_, _, err := client.GatewayCreateProducerCustom(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerCustomRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GatewayGetProducer{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GatewayGetProducer(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}
	if rOut.CreateSyncUrl != nil {
		err = d.Set("create_sync_url", *rOut.CreateSyncUrl)
		if err != nil {
			return err
		}
	}
	if rOut.RevokeSyncUrl != nil {
		err = d.Set("revoke_sync_url", *rOut.RevokeSyncUrl)
		if err != nil {
			return err
		}
	}
	if rOut.RotateSyncUrl != nil {
		err = d.Set("rotate_sync_url", *rOut.RotateSyncUrl)
		if err != nil {
			return err
		}
	}
	if rOut.Payload != nil {
		err = d.Set("payload", *rOut.Payload)
		if err != nil {
			return err
		}
	}
	if rOut.TimeoutSeconds != nil {
		err = d.Set("timeout_sec", *rOut.TimeoutSeconds)
		if err != nil {
			return err
		}
	}
	if rOut.UserTtl != nil {
		err = d.Set("user_ttl", *rOut.UserTtl)
		if err != nil {
			return err
		}
	}
	if rOut.Tags != nil {
		err = d.Set("tags", *rOut.Tags)
		if err != nil {
			return err
		}
	}
	if rOut.DynamicSecretKey != nil {
		err = d.Set("producer_encryption_key_name", *rOut.DynamicSecretKey)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceProducerCustomUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	createSyncUrl := d.Get("create_sync_url").(string)
	name := d.Get("name").(string)
	payload := d.Get("payload").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	revokeSyncUrl := d.Get("revoke_sync_url").(string)
	rotateSyncUrl := d.Get("rotate_sync_url").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	timeoutSec := d.Get("timeout_sec").(int)
	userTtl := d.Get("user_ttl").(string)

	body := akeyless.GatewayUpdateProducerCustom{
		Name:  name,
		Token: &token,
	}

	common.GetAkeylessPtr(&body.CreateSyncUrl, createSyncUrl)
	common.GetAkeylessPtr(&body.Name, name)
	common.GetAkeylessPtr(&body.Payload, payload)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.RevokeSyncUrl, revokeSyncUrl)
	common.GetAkeylessPtr(&body.RotateSyncUrl, rotateSyncUrl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.TimeoutSec, timeoutSec)
	common.GetAkeylessPtr(&body.Token, token)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)

	_, _, err := client.GatewayUpdateProducerCustom(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerCustomDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.GatewayDeleteProducer{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.GatewayDeleteProducer(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceProducerCustomImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GatewayGetProducer{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GatewayGetProducer(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
