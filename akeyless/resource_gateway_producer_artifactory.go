// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceProducerArtifactory() *schema.Resource {
	return &schema.Resource{
		Description: "Artifactory producer resource",
		Create:      resourceProducerArtifactoryCreate,
		Read:        resourceProducerArtifactoryRead,
		Update:      resourceProducerArtifactoryUpdate,
		Delete:      resourceProducerArtifactoryDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerArtifactoryImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Producer name",
				ForceNew:    true,
			},
			"artifactory_token_scope": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Token scope provided as a space-separated list, for example: member-of-groups:readers",
			},
			"artifactory_token_audience": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A space-separate list of the other Artifactory instances or services that should accept this token., for example: jfrt@*",
			},
			"target_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Name of existing target to use in producer creation",
			},
			"base_url": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Artifactory REST URL, must end with artifactory postfix",
			},
			"artifactory_admin_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Admin name",
			},
			"artifactory_admin_pwd": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Admin API Key/Password",
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
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceProducerArtifactoryCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	artifactoryTokenScope := d.Get("artifactory_token_scope").(string)
	artifactoryTokenAudience := d.Get("artifactory_token_audience").(string)
	targetName := d.Get("target_name").(string)
	baseUrl := d.Get("base_url").(string)
	artifactoryAdminName := d.Get("artifactory_admin_name").(string)
	artifactoryAdminPwd := d.Get("artifactory_admin_pwd").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless.GatewayCreateProducerArtifactory{
		Name:                     name,
		ArtifactoryTokenScope:    artifactoryTokenScope,
		ArtifactoryTokenAudience: artifactoryTokenAudience,
		Token:                    &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.BaseUrl, baseUrl)
	common.GetAkeylessPtr(&body.ArtifactoryAdminName, artifactoryAdminName)
	common.GetAkeylessPtr(&body.ArtifactoryAdminPwd, artifactoryAdminPwd)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)

	_, _, err := client.GatewayCreateProducerArtifactory(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerArtifactoryRead(d *schema.ResourceData, m interface{}) error {
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
	if rOut.ArtifactoryTokenScope != nil {
		err = d.Set("artifactory_token_scope", *rOut.ArtifactoryTokenScope)
		if err != nil {
			return err
		}
	}
	if rOut.ArtifactoryTokenAudience != nil {
		err = d.Set("artifactory_token_audience", *rOut.ArtifactoryTokenAudience)
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
	if rOut.ArtifactoryBaseUrl != nil {
		err = d.Set("base_url", *rOut.ArtifactoryBaseUrl)
		if err != nil {
			return err
		}
	}
	if rOut.ArtifactoryAdminUsername != nil {
		err = d.Set("artifactory_admin_name", *rOut.ArtifactoryAdminUsername)
		if err != nil {
			return err
		}
	}
	if rOut.ArtifactoryAdminApikey != nil {
		err = d.Set("artifactory_admin_pwd", *rOut.ArtifactoryAdminApikey)
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

func resourceProducerArtifactoryUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	artifactoryTokenScope := d.Get("artifactory_token_scope").(string)
	artifactoryTokenAudience := d.Get("artifactory_token_audience").(string)
	targetName := d.Get("target_name").(string)
	baseUrl := d.Get("base_url").(string)
	artifactoryAdminName := d.Get("artifactory_admin_name").(string)
	artifactoryAdminPwd := d.Get("artifactory_admin_pwd").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless.GatewayUpdateProducerArtifactory{
		Name:                     name,
		ArtifactoryTokenScope:    artifactoryTokenScope,
		ArtifactoryTokenAudience: artifactoryTokenAudience,
		Token:                    &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.BaseUrl, baseUrl)
	common.GetAkeylessPtr(&body.ArtifactoryAdminName, artifactoryAdminName)
	common.GetAkeylessPtr(&body.ArtifactoryAdminPwd, artifactoryAdminPwd)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)

	_, _, err := client.GatewayUpdateProducerArtifactory(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerArtifactoryDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceProducerArtifactoryImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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
