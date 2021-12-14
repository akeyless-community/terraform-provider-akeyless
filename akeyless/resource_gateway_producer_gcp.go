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

func resourceProducerGcp() *schema.Resource {
	return &schema.Resource{
		Description: "Google Cloud Provider (GCP)  producer resource",
		Create:      resourceProducerGcpCreate,
		Read:        resourceProducerGcpRead,
		Update:      resourceProducerGcpUpdate,
		Delete:      resourceProducerGcpDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerGcpImport,
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
			"gcp_sa_email": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "GCP service account email",
			},
			"gcp_cred_type": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Credentials type, options are [token, key]",
				Default:     "token",
			},
			"gcp_key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Base64-encoded service account private key text",
			},
			"gcp_token_scopes": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Access token scopes list, e.g. scope1,scope2",
			},
			"gcp_key_algo": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Service account key algorithm, e.g. KEY_ALG_RSA_1024",
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

func resourceProducerGcpCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	gcpSaEmail := d.Get("gcp_sa_email").(string)
	gcpCredType := d.Get("gcp_cred_type").(string)
	gcpKey := d.Get("gcp_key").(string)
	gcpTokenScopes := d.Get("gcp_token_scopes").(string)
	gcpKeyAlgo := d.Get("gcp_key_algo").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)

	body := akeyless.GatewayCreateProducerGcp{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.GcpSaEmail, gcpSaEmail)
	common.GetAkeylessPtr(&body.GcpCredType, gcpCredType)
	common.GetAkeylessPtr(&body.GcpKey, gcpKey)
	common.GetAkeylessPtr(&body.GcpTokenScopes, gcpTokenScopes)
	common.GetAkeylessPtr(&body.GcpKeyAlgo, gcpKeyAlgo)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)

	_, _, err := client.GatewayCreateProducerGcp(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerGcpRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.GcpKeyAlgo != nil {
		err = d.Set("gcp_key_algo", *rOut.GcpKeyAlgo)
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

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
		if err != nil {
			return err
		}
	}
	if rOut.GcpServiceAccountEmail != nil {
		err = d.Set("gcp_sa_email", *rOut.GcpServiceAccountEmail)
		if err != nil {
			return err
		}
	}
	if rOut.GcpTokenType != nil {
		err = d.Set("gcp_cred_type", *rOut.GcpTokenType)
		if err != nil {
			return err
		}
	}
	if rOut.GcpServiceAccountKey != nil {
		err = d.Set("gcp_key", *rOut.GcpServiceAccountKey)
		if err != nil {
			return err
		}
	}
	if rOut.GcpTokenScope != nil {
		err = d.Set("gcp_token_scopes", *rOut.GcpTokenScope)
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

func resourceProducerGcpUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	gcpSaEmail := d.Get("gcp_sa_email").(string)
	gcpCredType := d.Get("gcp_cred_type").(string)
	gcpKey := d.Get("gcp_key").(string)
	gcpTokenScopes := d.Get("gcp_token_scopes").(string)
	gcpKeyAlgo := d.Get("gcp_key_algo").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)

	body := akeyless.GatewayUpdateProducerGcp{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.GcpSaEmail, gcpSaEmail)
	common.GetAkeylessPtr(&body.GcpCredType, gcpCredType)
	common.GetAkeylessPtr(&body.GcpKey, gcpKey)
	common.GetAkeylessPtr(&body.GcpTokenScopes, gcpTokenScopes)
	common.GetAkeylessPtr(&body.GcpKeyAlgo, gcpKeyAlgo)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)

	_, _, err := client.GatewayUpdateProducerGcp(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerGcpDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceProducerGcpImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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
