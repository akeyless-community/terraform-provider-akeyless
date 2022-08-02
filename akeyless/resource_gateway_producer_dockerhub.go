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

func resourceProducerDockerhub() *schema.Resource {
	return &schema.Resource{
		Description: "Creates a Dockerhub producer",
		Create:      resourceProducerDockerhubCreate,
		Read:        resourceProducerDockerhubRead,
		Update:      resourceProducerDockerhubUpdate,
		Delete:      resourceProducerDockerhubDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerDockerhubImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Producer name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Name of existing target to use in producer creation",
			},
			"dockerhub_username": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Username for docker repository",
			},
			"dockerhub_password": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Password for docker repository",
			},
			"dockerhub_token_scopes": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Comma seperated access token scopes list to give the created dynamic secret. Valid options are in 'repo:admin', 'repo:write', 'repo:read', 'repo:public_read'",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "User TTL (<=60m for access token)",
				Default:     "60m",
			},
			"tags": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: --tag Tag1 --tag Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"producer_encryption_key_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Dynamic producer encryption key",
			},
		},
	}
}

func resourceProducerDockerhubCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	dockerhubUsername := d.Get("dockerhub_username").(string)
	dockerhubPassword := d.Get("dockerhub_password").(string)
	dockerhubTokenScopes := d.Get("dockerhub_token_scopes").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)

	body := akeyless.GatewayCreateProducerDockerhub{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.DockerhubUsername, dockerhubUsername)
	common.GetAkeylessPtr(&body.DockerhubPassword, dockerhubPassword)
	common.GetAkeylessPtr(&body.DockerhubTokenScopes, dockerhubTokenScopes)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)

	_, _, err := client.GatewayCreateProducerDockerhub(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerDockerhubRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
		if err != nil {
			return err
		}
	}
	if rOut.UserName != nil {
		err = d.Set("dockerhub_username", *rOut.UserName)
		if err != nil {
			return err
		}
	}
	if rOut.Password != nil {
		err = d.Set("dockerhub_password", *rOut.Password)
		if err != nil {
			return err
		}
	}

	if rOut.Scopes != nil {
		scopes := *rOut.Scopes
		var scopeString = ""
		for _, scope := range scopes {
			scopeString = scopeString + scope + " , "
		}
		// remove the last ` , ` from end of string
		scopeString = scopeString[:len(scopeString)-3]
		err = d.Set("dockerhub_token_scopes", scopeString)
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

func resourceProducerDockerhubUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	dockerhubUsername := d.Get("dockerhub_username").(string)
	dockerhubPassword := d.Get("dockerhub_password").(string)
	dockerhubTokenScopes := d.Get("dockerhub_token_scopes").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)

	body := akeyless.GatewayUpdateProducerDockerhub{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.DockerhubUsername, dockerhubUsername)
	common.GetAkeylessPtr(&body.DockerhubPassword, dockerhubPassword)
	common.GetAkeylessPtr(&body.DockerhubTokenScopes, dockerhubTokenScopes)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)

	_, _, err := client.GatewayUpdateProducerDockerhub(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerDockerhubDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceProducerDockerhubImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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
